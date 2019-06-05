/* BSD 3-Clause License
 *
 * Copyright (c) 2017, John Baublitz
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// The impl_var macro is private in neli 0.3.1. It's publicly exported in the
// pending neli 0.4.0 release (as of 2019-03-21). We can work around the fact
// that 0.4.0 isn't released yet by copying the macro source from 0.3.1 for now.
//
// The following comes from:
// https://docs.rs/crate/neli/0.3.1/source/src/ffi.rs

macro_rules! impl_var {
    ( $name:ident, $ty:ty, $var_def:ident => $val_def:expr,
      $( $var:ident => $val:expr ),* ) => (

        /// Enum representing C constants for netlink packets
        #[derive(Clone,Debug,Eq,PartialEq)]
        pub enum $name {
            #[allow(missing_docs)]
            $var_def,
            $(
                #[allow(missing_docs)]
                $var,
            )*
            /// Variant that signifies an invalid value while deserializing
            UnrecognizedVariant($ty),
        }

        impl From<$ty> for $name {
            fn from(v: $ty) -> Self {
                match v {
                    i if i == $val_def => $name::$var_def,
                    $( i if i == $val => $name::$var, )*
                    i => $name::UnrecognizedVariant(i)
                }
            }
        }

        impl From<$name> for $ty {
            fn from(v: $name) -> Self {
                match v {
                    $name::$var_def => $val_def,
                    $( $name::$var => $val, )*
                    $name::UnrecognizedVariant(i) => i,
                }
            }
        }

        impl neli::Nl for $name {
            type SerIn = ();
            type DeIn = ();

            fn serialize(&self, mem: &mut buffering::copy::StreamWriteBuffer) -> Result<(), neli::err::SerError> {
                let v: $ty = self.clone().into();
                v.serialize(mem)
            }

            fn deserialize<T>(mem: &mut buffering::copy::StreamReadBuffer<T>) -> Result<Self, neli::err::DeError>
                    where T: AsRef<[u8]> {
                let v: $ty = neli::Nl::deserialize(mem)?;
                Ok(v.into())
            }

            fn size(&self) -> usize {
                std::mem::size_of::<$ty>()
            }
        }
    );
}
