// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! This module defines `HostState` and `HostContext` structs which provide logic and state
//! required for execution of host.

use crate::{instance_wrapper::MemoryWrapper, runtime::StoreData, util};
use sc_allocator::{AllocationStats, FreeingBumpHeapAllocator};
use sp_virtualization::{
	Memory as VirtMemory, MemoryT, SharedState as VirtSharedState, Virt, VirtT,
};
use sp_wasm_interface::{Pointer, WordSize};
use std::{collections::HashMap, mem};
use wasmtime::{AsContext, Caller, TypedFunc};

/// The state required to construct a HostContext context. The context only lasts for one host
/// call, whereas the state is maintained for the duration of a Wasm runtime call, which may make
/// many different host calls that must share state.
pub struct HostState {
	/// The allocator instance to keep track of allocated memory.
	///
	/// This is stored as an `Option` as we need to temporarily set this to `None` when we are
	/// allocating/deallocating memory. The problem being that we can only mutable access `caller`
	/// once.
	allocator: Option<FreeingBumpHeapAllocator>,
	panic_message: Option<String>,
	virt_instances: HashMap<u64, VirtOrMem>,
	virt_counter: u64,
}

impl HostState {
	/// Constructs a new `HostState`.
	pub fn new(allocator: FreeingBumpHeapAllocator) -> Self {
		HostState {
			allocator: Some(allocator),
			panic_message: None,
			virt_instances: Default::default(),
			virt_counter: 0,
		}
	}

	/// Takes the error message out of the host state, leaving a `None` in its place.
	pub fn take_panic_message(&mut self) -> Option<String> {
		self.panic_message.take()
	}

	pub(crate) fn allocation_stats(&self) -> AllocationStats {
		self.allocator.as_ref()
			.expect("Allocator is always set and only unavailable when doing an allocation/deallocation; qed")
			.stats()
	}
}

/// A `HostContext` implements `FunctionContext` for making host calls from a Wasmtime
/// runtime. The `HostContext` exists only for the lifetime of the call and borrows state from
/// a longer-living `HostState`.
pub(crate) struct HostContext<'a> {
	pub(crate) caller: Caller<'a, StoreData>,
}

impl<'a> HostContext<'a> {
	fn host_state_mut(&mut self) -> &mut HostState {
		self.caller
			.data_mut()
			.host_state_mut()
			.expect("host state is not empty when calling a function in wasm; qed")
	}
}

impl<'a> sp_wasm_interface::FunctionContext for HostContext<'a> {
	fn read_memory_into(
		&self,
		address: Pointer<u8>,
		dest: &mut [u8],
	) -> sp_wasm_interface::Result<()> {
		util::read_memory_into(&self.caller, address, dest).map_err(|e| e.to_string())
	}

	fn write_memory(&mut self, address: Pointer<u8>, data: &[u8]) -> sp_wasm_interface::Result<()> {
		util::write_memory_from(&mut self.caller, address, data).map_err(|e| e.to_string())
	}

	fn allocate_memory(&mut self, size: WordSize) -> sp_wasm_interface::Result<Pointer<u8>> {
		let memory = self.caller.data().memory();
		let mut allocator = self
			.host_state_mut()
			.allocator
			.take()
			.expect("allocator is not empty when calling a function in wasm; qed");

		// We can not return on error early, as we need to store back allocator.
		let res = allocator
			.allocate(&mut MemoryWrapper(&memory, &mut self.caller), size)
			.map_err(|e| e.to_string());

		self.host_state_mut().allocator = Some(allocator);

		res
	}

	fn deallocate_memory(&mut self, ptr: Pointer<u8>) -> sp_wasm_interface::Result<()> {
		let memory = self.caller.data().memory();
		let mut allocator = self
			.host_state_mut()
			.allocator
			.take()
			.expect("allocator is not empty when calling a function in wasm; qed");

		// We can not return on error early, as we need to store back allocator.
		let res = allocator
			.deallocate(&mut MemoryWrapper(&memory, &mut self.caller), ptr)
			.map_err(|e| e.to_string());

		self.host_state_mut().allocator = Some(allocator);

		res
	}

	fn register_panic_error_message(&mut self, message: &str) {
		self.host_state_mut().panic_message = Some(message.to_owned());
	}

	fn virtualization(&mut self) -> &mut dyn sp_wasm_interface::Virtualization {
		self
	}
}

impl<'a> sp_wasm_interface::Virtualization for HostContext<'a> {
	fn instantiate(&mut self, program: &[u8]) -> sp_wasm_interface::Result<Result<u64, u8>> {
		let virt = match Virt::instantiate(program) {
			Ok(virt) => virt,
			Err(err) => return Ok(Err(err.into())),
		};

		let host = self.host_state_mut();

		let instance_id = {
			let old = host.virt_counter;
			host.virt_counter = old + 1;
			old
		};

		host.virt_instances.insert(instance_id, VirtOrMem::Instance(virt));

		Ok(Ok(instance_id))
	}

	fn execute(
		&mut self,
		instance_id: u64,
		function: &str,
		syscall_handler: u32,
		state_ptr: u32,
	) -> sp_wasm_interface::Result<Result<(), u8>> {
		let virt = match self
			.host_state_mut()
			.virt_instances
			.remove(&instance_id)
			.ok_or("invalid virt instance id")?
		{
			VirtOrMem::Instance(virt) => virt,
			VirtOrMem::Memory(_) => Err("it is illegal to call execute while already executing")?,
		};

		// Extract a syscall handler from the instance's table by the specified index.
		let syscall_handler = {
			let table = self
				.caller
				.data()
				.table
				.ok_or("Runtime doesn't have a table; sandbox is unavailable")?;
			let table_item = table.get(&mut self.caller, syscall_handler);

			table_item
				.ok_or("dispatch_thunk_id is out of bounds")?
				.funcref()
				.ok_or("dispatch_thunk_idx should be a funcref")?
				.ok_or("dispatch_thunk_idx should point to actual func")?
				.typed(&mut self.caller)
				.map_err(|_| "dispatch_thunk_idx has the wrong type")?
		};

		self.host_state_mut()
			.virt_instances
			.insert(instance_id, VirtOrMem::Memory(virt.memory()));

		let mut shared_state = VirtSharedState {
			gas_left: 0,
			exit: false,
			user: VirtContext { host: self, syscall_handler, state_ptr },
		};

		let outcome = virt.execute(function, virt_syscall_handler, &mut shared_state);

		self.host_state_mut().virt_instances.remove(&instance_id);

		Ok(outcome.map_err(Into::into))
	}

	fn read_memory(
		&mut self,
		instance_id: u64,
		offset: u32,
		buf_ptr: u32,
		buf_len: u32,
	) -> sp_wasm_interface::Result<Result<(), u8>> {
		let memory = self
			.host_state_mut()
			.virt_instances
			.get(&instance_id)
			.ok_or("invalid virt instance id")?
			.memory();
		let mut buf = vec![0u8; buf_len as usize];
		if let Err(err) = memory.read(offset, buf.as_mut()) {
			return Ok(Err(err.into()))
		}
		util::write_memory_from(&mut self.caller, buf_ptr.into(), buf.as_ref())
			.map_err(|_| "Failed to write memory from the virt instance to the supervisor")?;
		Ok(Ok(()))
	}

	fn write_memory(
		&mut self,
		instance_id: u64,
		offset: u32,
		buf_ptr: u32,
		buf_len: u32,
	) -> sp_wasm_interface::Result<Result<(), u8>> {
		let mut memory = self
			.host_state_mut()
			.virt_instances
			.get(&instance_id)
			.ok_or("invalid virt instance id")?
			.memory();
		let mut buf = vec![0u8; buf_len as usize];
		util::read_memory_into(&self.caller, buf_ptr.into(), buf.as_mut())
			.map_err(|_| "Failed to read memory from supervisor")?;
		if let Err(err) = memory.write(offset, buf.as_ref()) {
			return Ok(Err(err.into()))
		}
		Ok(Ok(()))
	}
}

enum VirtOrMem {
	Instance(Virt),
	Memory(VirtMemory),
}

impl VirtOrMem {
	fn memory(&self) -> VirtMemory {
		match self {
			Self::Instance(virt) => virt.memory(),
			Self::Memory(memory) => memory.clone(),
		}
	}
}

/// Data structure that is passed into our registered callback.
struct VirtContext<'a, 'b> {
	/// Needed to get a wasm handler so we can call our `syscall_hander`
	host: &'a mut HostContext<'b>,
	/// Wasm function we call to handle our syscall.
	syscall_handler: TypedFunc<(u32, u32, u32, u32, u32, u32, u32, u32), u64>,
	/// First argument to the `syscall_handler`.
	state_ptr: u32,
}

impl<'a, 'b> VirtContext<'a, 'b> {
	fn state_in_wasm(&mut self) -> Option<&mut VirtSharedState<()>> {
		let offset = self.state_ptr as usize;
		let buf = self.host.caller.as_context().data().memory().data_mut(&mut self.host.caller);
		let scoped =
			buf.get_mut(offset..offset.saturating_add(mem::size_of::<VirtSharedState<()>>()))?;
		unsafe { Some(&mut *(scoped.as_mut_ptr() as *mut _)) }
	}
}

extern "C" fn virt_syscall_handler(
	state: &mut VirtSharedState<VirtContext<'_, '_>>,
	syscall_no: u32,
	a0: u32,
	a1: u32,
	a2: u32,
	a3: u32,
	a4: u32,
	a5: u32,
) -> u64 {
	let syscall_handler = state.user.syscall_handler;
	let state_ptr = state.user.state_ptr;

	// sync current gas counter to wasm
	if let Some(shared_state) = state.user.state_in_wasm() {
		shared_state.gas_left = state.gas_left;
	} else {
		// error out early of out of bound pointer was supplied
		state.exit = true;
		return u64::MAX
	}

	let result = syscall_handler
		.call(&mut state.user.host.caller, (state_ptr, syscall_no, a0, a1, a2, a3, a4, a5));
	match result {
		Ok(outcome) => {
			// those fields could have been changes by handler: copy back from wasm
			let shared_state = state.user.state_in_wasm().expect("was checked above; qed");
			state.gas_left = shared_state.gas_left;
			state.exit = shared_state.exit;
			outcome
		},
		Err(err) => {
			log::error!("RiscV syscall handler failed: {}", err);
			// we trap the execution. return value is not used in this case.
			state.exit = true;
			u64::MAX
		},
	}
}
