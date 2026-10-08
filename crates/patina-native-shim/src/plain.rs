#![deny(clippy::undocumented_unsafe_blocks)]

/// A type whose representation has no padding and accepts every bit pattern.
///
/// # Safety
/// Every byte pattern, including all zeroes, must be a valid `Self`, and
/// `Self` must have no padding bytes.
pub(crate) unsafe trait Plain: Copy + 'static {}

// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for u8 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for u16 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for u32 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for u64 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for u128 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for usize {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for i8 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for i16 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for i32 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for i64 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for i128 {}
// SAFETY: Integers have no padding and every bit pattern is valid.
unsafe impl Plain for isize {}

// SAFETY: Floating-point values have no padding and every bit pattern is valid.
unsafe impl Plain for f32 {}
// SAFETY: Floating-point values have no padding and every bit pattern is valid.
unsafe impl Plain for f64 {}

// SAFETY: A plain array contains only plain elements, with no inter-element or
// trailing padding, and every element bit pattern is valid.
unsafe impl<T: Plain, const N: usize> Plain for [T; N] {}

/// Implement `Plain` for an integer-only struct and prove that its fields leave
/// no padding. The pattern lists every field and binds it by value, so it also
/// works for packed structs.
#[doc(hidden)]
#[macro_export]
macro_rules! plain {
    ($ty:path { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        const _: () = assert!(
            ::core::mem::size_of::<$ty>()
                == 0usize $(+ ::core::mem::size_of::<$field_ty>())+
        );

        const _: fn(&$ty) = |value| {
            fn assert_plain<T: $crate::plain::Plain>() {}

            let $ty { $($field),+ } = *value;
            $(
                let _: $field_ty = $field;
                assert_plain::<$field_ty>();
            )+
        };

        // SAFETY: the exhaustive pattern checks every field by value, each
        // field type implements Plain, and the size assertion proves no padding.
        unsafe impl $crate::plain::Plain for $ty {}
    };
}

/// Return a valid all-zero value of `T`.
#[allow(dead_code)]
pub(crate) fn zeroed<T: Plain>() -> T {
    // SAFETY: `Plain` guarantees that the all-zero byte pattern is valid for `T`.
    unsafe { core::mem::zeroed() }
}

/// View a plain value as its complete byte representation.
#[allow(dead_code)]
pub(crate) fn bytes<T: Plain>(value: &T) -> &[u8] {
    // SAFETY: `Plain` guarantees every byte is initialized and that no padding
    // lies within the value's representation.
    unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    }
}

/// View a plain value as its complete mutable byte representation.
#[allow(dead_code)]
pub(crate) fn bytes_mut<T: Plain>(value: &mut T) -> &mut [u8] {
    // SAFETY: `Plain` guarantees every byte is initialized and that no padding
    // lies within the value's representation; `&mut T` uniquely borrows it.
    unsafe {
        core::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), core::mem::size_of::<T>())
    }
}

/// Store a plain value at an aligned destination.
///
/// # Safety
/// `destination` must be aligned and valid for writing one `T`.
#[allow(dead_code)]
pub(crate) unsafe fn store<T: Plain>(destination: *mut T, value: T) {
    // SAFETY: the caller guarantees that `destination` is aligned and writable for one `T`.
    unsafe { destination.write(value) };
}

/// Store a plain value at a destination that may be unaligned.
///
/// # Safety
/// `destination` must be valid for writing one `T`.
#[allow(dead_code)]
pub(crate) unsafe fn store_unaligned<T: Plain>(destination: *mut T, value: T) {
    // SAFETY: the caller guarantees that `destination` is writable for one `T`; unaligned writes
    // do not require an alignment invariant.
    unsafe { destination.write_unaligned(value) };
}
