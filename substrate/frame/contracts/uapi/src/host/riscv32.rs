#![allow(unused_variables, unused_mut)]
// Copyright (C) Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// TODO: bring up to date with wasm32.rs

use crate::{
	host::{
		extract_from_slice, ptr_len_or_sentinel, ptr_or_sentinel, CallFlags, HostFn, HostFnImpl,
		Result,
	},
	ReturnFlags,
};

mod sys {
	use crate::ReturnCode;

	#[polkavm_derive::polkavm_define_abi]
	mod abi {}

	impl abi::FromHost for ReturnCode {
		type Regs = (u32,);

		fn from_host((a0,): Self::Regs) -> Self {
			ReturnCode(a0)
		}
	}

	#[polkavm_derive::polkavm_import(abi = self::abi)]
	extern "C" {
		#[polkavm_import(symbol = 1u32)]
		pub fn set_storage_v2(
			key_ptr: *const u8,
			key_len: u32,
			value_ptr: *const u8,
			value_len: u32,
		) -> ReturnCode;

		#[polkavm_import(symbol = 2u32)]
		pub fn clear_storage_v1(key_ptr: *const u8, key_len: u32) -> u32;

		#[polkavm_import(symbol = 3u32)]
		pub fn get_storage_v1(
			key_ptr: *const u8,
			key_len: u32,
			out_ptr: *mut u8,
			out_len_ptr: *mut u32,
		) -> ReturnCode;

		#[polkavm_import(symbol = 4u32)]
		pub fn contains_storage_v1(key_ptr: *const u8, key_len: u32) -> u32;

		#[polkavm_import(symbol = 5u32)]
		pub fn take_storage(
			key_ptr: *const u8,
			key_len: u32,
			out_ptr: *mut u8,
			out_len_ptr: *mut u32,
		) -> ReturnCode;

		#[polkavm_import(symbol = 6u32)]
		pub fn transfer_v1(account_ptr: *const u8, value_ptr: *const u8) -> ReturnCode;

		#[polkavm_import(symbol = 8u32)]
		pub fn call_v2(ptr: *const u8) -> ReturnCode;

		#[polkavm_import(symbol = 9u32)]
		pub fn delegate_call(
			flags: u32,
			code_hash_ptr: *const u8,
			input_data_ptr: *const u8,
			input_data_len: u32,
			out_ptr: *mut u8,
			out_len_ptr: *mut u32,
		) -> ReturnCode;

		#[polkavm_import(symbol = 11u32)]
		pub fn instantiate_v2(ptr: *const u8) -> ReturnCode;

		#[polkavm_import(symbol = 12u32)]
		pub fn terminate_v1(beneficiary_ptr: *const u8);

		#[polkavm_import(symbol = 13u32)]
		pub fn input(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 14u32)]
		pub fn seal_return(flags: u32, data_ptr: *const u8, data_len: u32);

		#[polkavm_import(symbol = 15u32)]
		pub fn caller(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 16u32)]
		pub fn is_contract(account_ptr: *const u8) -> ReturnCode;

		#[polkavm_import(symbol = 17u32)]
		pub fn code_hash(
			account_ptr: *const u8,
			out_ptr: *mut u8,
			out_len_ptr: *mut u32,
		) -> ReturnCode;

		#[polkavm_import(symbol = 18u32)]
		pub fn own_code_hash(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 19u32)]
		pub fn caller_is_origin() -> ReturnCode;

		#[polkavm_import(symbol = 20u32)]
		pub fn caller_is_root() -> ReturnCode;

		#[polkavm_import(symbol = 21u32)]
		pub fn address(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 22u32)]
		pub fn weight_to_fee(gas: u64, out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 23u32)]
		pub fn weight_to_fee_v1(
			ref_time: u64,
			proof_size: u64,
			out_ptr: *mut u8,
			out_len_ptr: *mut u32,
		);

		#[polkavm_import(symbol = 24u32)]
		pub fn gas_left(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 25u32)]
		pub fn gas_left_v1(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 26u32)]
		pub fn balance(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 27u32)]
		pub fn value_transferred(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 28u32)]
		pub fn now(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 29u32)]
		pub fn minimum_balance(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 30u32)]
		pub fn deposit_event(
			topics_ptr: *const u8,
			topics_len: u32,
			data_ptr: *const u8,
			data_len: u32,
		);

		#[polkavm_import(symbol = 31u32)]
		pub fn block_number(out_ptr: *mut u8, out_len_ptr: *mut u32);

		#[polkavm_import(symbol = 32u32)]
		pub fn hash_sha2_256(input_ptr: *const u8, input_len: u32, out_ptr: *mut u8);

		#[polkavm_import(symbol = 33u32)]
		pub fn hash_keccak_256(input_ptr: *const u8, input_len: u32, out_ptr: *mut u8);

		#[polkavm_import(symbol = 34u32)]
		pub fn hash_blake2_256(input_ptr: *const u8, input_len: u32, out_ptr: *mut u8);

		#[polkavm_import(symbol = 35u32)]
		pub fn hash_blake2_128(input_ptr: *const u8, input_len: u32, out_ptr: *mut u8);

		#[polkavm_import(symbol = 36u32)]
		pub fn call_chain_extension(
			id: u32,
			input_ptr: *const u8,
			input_len: u32,
			out_ptr: *mut u8,
			out_len_ptr: *mut u32,
		) -> ReturnCode;

		#[polkavm_import(symbol = 37u32)]
		pub fn debug_message(str_ptr: *const u8, str_len: u32) -> ReturnCode;

		#[polkavm_import(symbol = 38u32)]
		pub fn call_runtime(call_ptr: *const u8, call_len: u32) -> ReturnCode;

		#[polkavm_import(symbol = 39u32)]
		pub fn ecdsa_recover(
			signature_ptr: *const u8,
			message_hash_ptr: *const u8,
			out_ptr: *mut u8,
		) -> ReturnCode;

		#[polkavm_import(symbol = 40u32)]
		pub fn sr25519_verify(
			signature_ptr: *const u8,
			pub_key_ptr: *const u8,
			message_len: u32,
			message_ptr: *const u8,
		) -> ReturnCode;

		#[polkavm_import(symbol = 41u32)]
		pub fn set_code_hash(code_hash_ptr: *const u8) -> ReturnCode;

		#[polkavm_import(symbol = 42u32)]
		pub fn ecdsa_to_eth_address(key_ptr: *const u8, out_ptr: *mut u8) -> ReturnCode;

		#[polkavm_import(symbol = 43u32)]
		pub fn reentrance_count() -> u32;

		#[polkavm_import(symbol = 44u32)]
		pub fn account_reentrance_count(account_ptr: *const u8) -> u32;

		#[polkavm_import(symbol = 45u32)]
		pub fn instantiation_nonce() -> u64;

		#[polkavm_import(symbol = 46u32)]
		pub fn lock_delegate_dependency(code_hash_ptr: *const u8);

		#[polkavm_import(symbol = 47u32)]
		pub fn unlock_delegate_dependency(code_hash_ptr: *const u8);

		#[polkavm_import(symbol = 48u32)]
		pub fn xcm_execute(msg_ptr: *const u8, msg_len: u32) -> ReturnCode;

		#[polkavm_import(symbol = 49u32)]
		pub fn xcm_send(
			dest_ptr: *const u8,
			msg_ptr: *const u8,
			msg_len: u32,
			out_ptr: *mut u8,
		) -> ReturnCode;
	}
}

macro_rules! impl_wrapper_for {
    ( $( $name:ident, )* ) => {
        $(
            fn $name(output: &mut &mut [u8]) {
                let mut output_len = output.len() as u32;
                unsafe {
                    sys::$name(
                        output.as_mut_ptr(),
                        &mut output_len,
                    )
                }
                extract_from_slice(output, output_len as usize)
            }
        )*
    }
}

macro_rules! impl_hash_fn {
	( $name:ident, $bytes_result:literal ) => {
		paste::item! {
			fn [<hash_ $name>](input: &[u8], output: &mut [u8; $bytes_result]) {
				unsafe {
					sys::[<hash_ $name>](
						input.as_ptr(),
						input.len() as u32,
						output.as_mut_ptr(),
					)
				}
			}
		}
	};
}

impl HostFn for HostFnImpl {
	fn instantiate_v1(
		code_hash: &[u8],
		gas: u64,
		value: &[u8],
		input: &[u8],
		mut address: Option<&mut &mut [u8]>,
		mut output: Option<&mut &mut [u8]>,
		salt: &[u8],
	) -> Result {
		unimplemented!()
	}

	fn instantiate_v2(
		code_hash: &[u8],
		ref_time_limit: u64,
		proof_size_limit: u64,
		deposit_limit: Option<&[u8]>,
		value: &[u8],
		input: &[u8],
		mut address: Option<&mut &mut [u8]>,
		mut output: Option<&mut &mut [u8]>,
		salt: &[u8],
	) -> Result {
		let (address_ptr, mut address_len) = ptr_len_or_sentinel(&mut address);
		let (output_ptr, mut output_len) = ptr_len_or_sentinel(&mut output);
		let deposit_limit_ptr = ptr_or_sentinel(&deposit_limit);
		#[repr(packed)]
		#[allow(dead_code)]
		struct Args {
			code_hash: *const u8,
			ref_time_limit: u64,
			proof_size_limit: u64,
			deposit_limit: *const u8,
			value: *const u8,
			input: *const u8,
			input_len: usize,
			address: *const u8,
			address_len: *mut u32,
			output: *mut u8,
			output_len: *mut u32,
			salt: *const u8,
			salt_len: usize,
		}
		let args = Args {
			code_hash: code_hash.as_ptr(),
			ref_time_limit,
			proof_size_limit,
			deposit_limit: deposit_limit_ptr,
			value: value.as_ptr(),
			input: input.as_ptr(),
			input_len: input.len(),
			address: address_ptr,
			address_len: &mut address_len as *mut _,
			output: output_ptr,
			output_len: &mut output_len as *mut _,
			salt: salt.as_ptr(),
			salt_len: salt.len(),
		};

		let ret_code = { unsafe { sys::instantiate_v2(&args as *const Args as *const _) } };

		if let Some(ref mut address) = address {
			extract_from_slice(address, address_len as usize);
		}

		if let Some(ref mut output) = output {
			extract_from_slice(output, output_len as usize);
		}

		ret_code.into()
	}

	fn call(
		callee: &[u8],
		gas: u64,
		value: &[u8],
		input_data: &[u8],
		mut output: Option<&mut &mut [u8]>,
	) -> Result {
		unimplemented!()
	}

	fn call_v1(
		flags: CallFlags,
		callee: &[u8],
		gas: u64,
		value: &[u8],
		input_data: &[u8],
		mut output: Option<&mut &mut [u8]>,
	) -> Result {
		unimplemented!()
	}

	fn call_v2(
		flags: CallFlags,
		callee: &[u8],
		ref_time_limit: u64,
		proof_size_limit: u64,
		deposit_limit: Option<&[u8]>,
		value: &[u8],
		input: &[u8],
		mut output: Option<&mut &mut [u8]>,
	) -> Result {
		let (output_ptr, mut output_len) = ptr_len_or_sentinel(&mut output);
		let deposit_limit_ptr = ptr_or_sentinel(&deposit_limit);
		#[repr(packed)]
		#[allow(dead_code)]
		struct Args {
			flags: u32,
			callee: *const u8,
			ref_time_limit: u64,
			proof_size_limit: u64,
			deposit_limit: *const u8,
			value: *const u8,
			input: *const u8,
			input_len: usize,
			output: *mut u8,
			output_len: *mut u32,
		}
		let args = Args {
			flags: flags.bits(),
			callee: callee.as_ptr(),
			ref_time_limit,
			proof_size_limit,
			deposit_limit: deposit_limit_ptr,
			value: value.as_ptr(),
			input: input.as_ptr(),
			input_len: input.len(),
			output: output_ptr,
			output_len: &mut output_len as *mut _,
		};

		let ret_code = { unsafe { sys::call_v2(&args as *const Args as *const _) } };

		if let Some(ref mut output) = output {
			extract_from_slice(output, output_len as usize);
		}

		ret_code.into()
	}

	fn caller_is_root() -> u32 {
		unsafe { sys::caller_is_root() }.into_u32()
	}

	fn delegate_call(
		flags: CallFlags,
		code_hash: &[u8],
		input: &[u8],
		mut output: Option<&mut &mut [u8]>,
	) -> Result {
		let (output_ptr, mut output_len) = ptr_len_or_sentinel(&mut output);
		let ret_code = {
			unsafe {
				sys::delegate_call(
					flags.bits(),
					code_hash.as_ptr(),
					input.as_ptr(),
					input.len() as u32,
					output_ptr,
					&mut output_len,
				)
			}
		};

		if let Some(ref mut output) = output {
			extract_from_slice(output, output_len as usize);
		}

		ret_code.into()
	}

	fn transfer(account_id: &[u8], value: &[u8]) -> Result {
		let ret_code = unsafe { sys::transfer_v1(account_id.as_ptr(), value.as_ptr()) };
		ret_code.into()
	}

	fn deposit_event(topics: &[u8], data: &[u8]) {
		unsafe {
			sys::deposit_event(
				topics.as_ptr(),
				topics.len() as u32,
				data.as_ptr(),
				data.len() as u32,
			)
		}
	}

	fn set_storage(key: &[u8], value: &[u8]) {
		unimplemented!()
	}

	fn set_storage_v1(key: &[u8], encoded_value: &[u8]) -> Option<u32> {
		unimplemented!()
	}

	fn set_storage_v2(key: &[u8], encoded_value: &[u8]) -> Option<u32> {
		let ret_code = unsafe {
			sys::set_storage_v2(
				key.as_ptr(),
				key.len() as u32,
				encoded_value.as_ptr(),
				encoded_value.len() as u32,
			)
		};
		ret_code.into()
	}

	fn clear_storage(key: &[u8]) {
		unimplemented!()
	}

	fn clear_storage_v1(key: &[u8]) -> Option<u32> {
		let ret_code = unsafe { sys::clear_storage_v1(key.as_ptr(), key.len() as u32) };
		ret_code.into()
	}

	fn get_storage(key: &[u8], output: &mut &mut [u8]) -> Result {
		unimplemented!()
	}

	fn get_storage_v1(key: &[u8], output: &mut &mut [u8]) -> Result {
		let mut output_len = output.len() as u32;
		let ret_code = {
			unsafe {
				sys::get_storage_v1(
					key.as_ptr(),
					key.len() as u32,
					output.as_mut_ptr(),
					&mut output_len,
				)
			}
		};
		extract_from_slice(output, output_len as usize);
		ret_code.into()
	}

	fn take_storage(key: &[u8], output: &mut &mut [u8]) -> Result {
		let mut output_len = output.len() as u32;
		let ret_code = {
			unsafe {
				sys::take_storage(
					key.as_ptr(),
					key.len() as u32,
					output.as_mut_ptr(),
					&mut output_len,
				)
			}
		};
		extract_from_slice(output, output_len as usize);
		ret_code.into()
	}

	fn debug_message(str: &[u8]) -> Result {
		let ret_code = unsafe { sys::debug_message(str.as_ptr(), str.len() as u32) };
		ret_code.into()
	}

	fn contains_storage(key: &[u8]) -> Option<u32> {
		unimplemented!()
	}

	fn contains_storage_v1(key: &[u8]) -> Option<u32> {
		let ret_code = unsafe { sys::contains_storage_v1(key.as_ptr(), key.len() as u32) };
		ret_code.into()
	}

	fn terminate(beneficiary: &[u8]) -> ! {
		unimplemented!()
	}

	fn terminate_v1(beneficiary: &[u8]) -> ! {
		unsafe { sys::terminate_v1(beneficiary.as_ptr()) }
		panic!("terminate does not return");
	}

	fn call_chain_extension(func_id: u32, input: &[u8], mut output: Option<&mut &mut [u8]>) -> u32 {
		let (output_ptr, mut output_len) = ptr_len_or_sentinel(&mut output);
		let ret_code = {
			unsafe {
				sys::call_chain_extension(
					func_id,
					input.as_ptr(),
					input.len() as u32,
					output_ptr,
					&mut output_len,
				)
			}
		};

		if let Some(ref mut output) = output {
			extract_from_slice(output, output_len as usize);
		}
		ret_code.into_u32()
	}

	fn input(output: &mut &mut [u8]) {
		let mut output_len = output.len() as u32;
		{
			unsafe { sys::input(output.as_mut_ptr(), &mut output_len) };
		}
		extract_from_slice(output, output_len as usize);
	}

	fn return_value(flags: ReturnFlags, return_value: &[u8]) -> ! {
		unsafe { sys::seal_return(flags.bits(), return_value.as_ptr(), return_value.len() as u32) }
		panic!("seal_return does not return");
	}

	fn call_runtime(call: &[u8]) -> Result {
		let ret_code = unsafe { sys::call_runtime(call.as_ptr(), call.len() as u32) };
		ret_code.into()
	}

	impl_wrapper_for! {
		caller, block_number, address, balance, gas_left, gas_left_v1,
		value_transferred,now, minimum_balance,
	}

	fn weight_to_fee(gas: u64, output: &mut &mut [u8]) {
		unimplemented!()
	}

	fn weight_to_fee_v1(ref_time_limit: u64, proof_size_limit: u64, output: &mut &mut [u8]) {
		let mut output_len = output.len() as u32;
		{
			unsafe {
				sys::weight_to_fee_v1(
					ref_time_limit,
					proof_size_limit,
					output.as_mut_ptr(),
					&mut output_len,
				)
			};
		}
		extract_from_slice(output, output_len as usize);
	}

	impl_hash_fn!(sha2_256, 32);
	impl_hash_fn!(keccak_256, 32);
	impl_hash_fn!(blake2_256, 32);
	impl_hash_fn!(blake2_128, 16);

	fn ecdsa_recover(
		signature: &[u8; 65],
		message_hash: &[u8; 32],
		output: &mut [u8; 33],
	) -> Result {
		let ret_code = unsafe {
			sys::ecdsa_recover(signature.as_ptr(), message_hash.as_ptr(), output.as_mut_ptr())
		};
		ret_code.into()
	}

	fn ecdsa_to_eth_address(pubkey: &[u8; 33], output: &mut [u8; 20]) -> Result {
		let ret_code = unsafe { sys::ecdsa_to_eth_address(pubkey.as_ptr(), output.as_mut_ptr()) };
		ret_code.into()
	}

	fn sr25519_verify(signature: &[u8; 64], message: &[u8], pub_key: &[u8; 32]) -> Result {
		let ret_code = unsafe {
			sys::sr25519_verify(
				signature.as_ptr(),
				pub_key.as_ptr(),
				message.len() as u32,
				message.as_ptr(),
			)
		};
		ret_code.into()
	}

	fn is_contract(account_id: &[u8]) -> bool {
		let ret_val = unsafe { sys::is_contract(account_id.as_ptr()) };
		ret_val.into_bool()
	}

	fn caller_is_origin() -> bool {
		let ret_val = unsafe { sys::caller_is_origin() };
		ret_val.into_bool()
	}

	fn set_code_hash(code_hash: &[u8]) -> Result {
		let ret_val = unsafe { sys::set_code_hash(code_hash.as_ptr()) };
		ret_val.into()
	}

	fn code_hash(account_id: &[u8], output: &mut [u8]) -> Result {
		let mut output_len = output.len() as u32;
		let ret_val =
			unsafe { sys::code_hash(account_id.as_ptr(), output.as_mut_ptr(), &mut output_len) };
		ret_val.into()
	}

	fn own_code_hash(output: &mut [u8]) {
		let mut output_len = output.len() as u32;
		unsafe { sys::own_code_hash(output.as_mut_ptr(), &mut output_len) }
	}

	fn account_reentrance_count(account: &[u8]) -> u32 {
		unsafe { sys::account_reentrance_count(account.as_ptr()) }
	}

	fn lock_delegate_dependency(code_hash: &[u8]) {
		unsafe { sys::lock_delegate_dependency(code_hash.as_ptr()) }
	}

	fn unlock_delegate_dependency(code_hash: &[u8]) {
		unsafe { sys::unlock_delegate_dependency(code_hash.as_ptr()) }
	}

	fn instantiation_nonce() -> u64 {
		unsafe { sys::instantiation_nonce() }
	}

	fn reentrance_count() -> u32 {
		unsafe { sys::reentrance_count() }
	}

	fn xcm_execute(msg: &[u8]) -> Result {
		let ret_code = unsafe { sys::xcm_execute(msg.as_ptr(), msg.len() as _) };
		ret_code.into()
	}

	fn xcm_send(dest: &[u8], msg: &[u8], output: &mut [u8; 32]) -> Result {
		let ret_code = unsafe {
			sys::xcm_send(dest.as_ptr(), msg.as_ptr(), msg.len() as _, output.as_mut_ptr())
		};
		ret_code.into()
	}
}
