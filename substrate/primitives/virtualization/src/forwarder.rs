// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
	ExecError, InstantiateError, MemoryError, MemoryT, SharedState, SyscallHandler, VirtT,
};
use sp_io::virtualization as host_fn;

pub struct Virt {
	instance_id: u64,
}

pub struct Memory {
	instance_id: u64,
}

impl VirtT for Virt {
	type Memory = Memory;

	fn instantiate(program: &[u8]) -> Result<Self, InstantiateError> {
		let instance_id = host_fn::instantiate(program)?;
		let virt = Self { instance_id };
		Ok(virt)
	}

	fn execute<T>(
		self,
		function: &str,
		syscall_handler: SyscallHandler<T>,
		shared_state: &mut SharedState<T>,
	) -> Result<(), ExecError> {
		host_fn::execute(
			self.instance_id,
			function,
			syscall_handler as u32,
			shared_state as *mut _ as usize as u32,
		)
	}

	fn memory(&self) -> Self::Memory {
		Memory { instance_id: self.instance_id }
	}
}

impl MemoryT for Memory {
	fn read(&self, offset: u32, dest: &mut [u8]) -> Result<(), MemoryError> {
		host_fn::read_memory(self.instance_id, offset, dest.as_mut_ptr() as u32, dest.len() as u32)
	}

	fn write(&mut self, offset: u32, src: &[u8]) -> Result<(), MemoryError> {
		host_fn::write_memory(self.instance_id, offset, src.as_ptr() as u32, src.len() as u32)
	}
}
