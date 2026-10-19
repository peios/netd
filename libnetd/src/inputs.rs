//! Validate C representations before handing owned data to the semantic core.

use std::io;
use std::mem::size_of;
use std::slice;
use std::str;

use netd_abi as abi;
use netd_core::raw::{RawKey, RawValue};
use pnp_core::Snapshot;

use crate::channel::invalid;

const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TREE_ITEMS: usize = 65_536;
const MAX_KEY_DEPTH: usize = 128;

pub(crate) unsafe fn array<'a, T>(pointer: *const T, count: usize) -> io::Result<&'a [T]> {
    if count == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() || count > isize::MAX as usize / size_of::<T>().max(1) {
        return Err(invalid("invalid array span"));
    }
    // SAFETY: caller guarantees count initialized, aligned elements in a live
    // allocation, borrowed for 'a. The checks satisfy Rust's null/size bounds.
    Ok(unsafe { slice::from_raw_parts(pointer, count) })
}

pub(crate) unsafe fn bytes<'a>(value: abi::Bytes) -> io::Result<&'a [u8]> {
    if value.len > MAX_TEXT_BYTES {
        return Err(invalid("input span exceeds 4 MiB"));
    }
    // SAFETY: forwarded from the caller's span lifetime and validity contract.
    unsafe { array(value.data, value.len) }
}

pub(crate) unsafe fn text<'a>(value: abi::Bytes) -> io::Result<&'a str> {
    // SAFETY: caller supplies a live borrowed byte span; UTF-8 is checked here.
    str::from_utf8(unsafe { bytes(value)? }).map_err(|_| invalid("text is not UTF-8"))
}

#[derive(Default)]
pub(crate) struct Budget {
    items: usize,
    text_bytes: usize,
}

impl Budget {
    fn items(&mut self, count: usize) -> io::Result<()> {
        self.items = self
            .items
            .checked_add(count)
            .filter(|count| *count <= MAX_TREE_ITEMS)
            .ok_or_else(|| invalid("configuration exceeds 65536 keys, values and list items"))?;
        Ok(())
    }

    unsafe fn text(&mut self, value: abi::Bytes) -> io::Result<String> {
        self.text_bytes = self
            .text_bytes
            .checked_add(value.len)
            .filter(|count| *count <= MAX_TEXT_BYTES)
            .ok_or_else(|| invalid("configuration text exceeds 4 MiB"))?;
        // SAFETY: the caller guarantees a readable span for this call.
        Ok(unsafe { text(value)? }.to_owned())
    }

    unsafe fn value(&mut self, value: &abi::Value) -> io::Result<(String, RawValue)> {
        // SAFETY: every active span in value follows the borrowed tree contract.
        let name = unsafe { self.text(value.name)? };
        let value = match value.kind {
            0 => RawValue::Other,
            1 => RawValue::Int(value.integer),
            2 => RawValue::Str(unsafe { self.text(value.text)? }),
            3 => {
                self.items(value.list.len)?;
                let items = unsafe { array(value.list.data, value.list.len)? };
                let items = items
                    .iter()
                    .map(|item| unsafe { self.text(*item) })
                    .collect::<io::Result<_>>()?;
                RawValue::List(items)
            }
            _ => return Err(invalid("unknown configuration value kind")),
        };
        Ok((name, value))
    }

    pub(crate) unsafe fn key(
        &mut self,
        pointer: *const abi::Key,
        depth: usize,
    ) -> io::Result<Option<RawKey>> {
        if pointer.is_null() {
            return Ok(None);
        }
        if depth >= MAX_KEY_DEPTH {
            return Err(invalid("configuration exceeds 128 key levels"));
        }
        self.items(1)?;
        // SAFETY: pointer is non-null and the caller guarantees a live aligned Key.
        let key = unsafe { &*pointer };
        self.items(key.value_count)?;
        // Check the child count before constructing or traversing the child slice.
        if key.child_count > MAX_TREE_ITEMS - self.items {
            return Err(invalid("too many child keys"));
        }
        // SAFETY: caller guarantees all reachable spans and arrays are readable.
        let (name, values, children) = unsafe {
            (
                self.text(key.name)?,
                array(key.values, key.value_count)?,
                array(key.children, key.child_count)?,
            )
        };
        let values = values
            .iter()
            .map(|value| {
                // SAFETY: each value belongs to the validated readable input slice.
                unsafe { self.value(value) }
            })
            .collect::<io::Result<_>>()?;
        let children = children
            .iter()
            .map(|child| {
                // SAFETY: each child belongs to the caller's readable input tree.
                unsafe { self.key(child, depth + 1) }
                    .map(|child| child.expect("non-null child reference"))
            })
            .collect::<io::Result<_>>()?;
        Ok(Some(RawKey {
            name,
            values,
            children,
        }))
    }
}

pub(crate) unsafe fn facts(pointer: *const abi::Facts) -> io::Result<Snapshot<'static>> {
    // SAFETY: a non-null pointer is a caller-owned readable Facts value.
    let facts = unsafe { pointer.as_ref() }.ok_or_else(|| invalid("null interface facts"))?;
    let mut budget = Budget::default();
    let mut optional = |span: abi::Bytes| {
        if span.data.is_null() {
            if span.len != 0 {
                return Err(invalid("null fact has a nonzero length"));
            }
            return Ok(None);
        }
        // SAFETY: each active fact span follows the caller's input contract.
        unsafe { budget.text(span) }.map(|text| Some(text.as_str().into()))
    };
    let interface_mac = if facts.interface_mac.data.is_null() && facts.interface_mac.len == 0 {
        None
    } else {
        // SAFETY: a present MAC is a caller-owned readable byte span.
        Some(
            unsafe { bytes(facts.interface_mac)? }
                .try_into()
                .map_err(|_| invalid("MAC must contain six bytes"))?,
        )
    };
    Ok(Snapshot {
        interface: optional(facts.interface)?,
        interface_kind: optional(facts.interface_kind)?,
        interface_id: optional(facts.interface_id)?,
        interface_mac,
        interface_path: optional(facts.interface_path)?,
        interface_driver: optional(facts.interface_driver)?,
        network_id: optional(facts.network_id)?,
        network_name: optional(facts.network_name)?,
        network_trust: optional(facts.network_trust)?,
        network_kind: optional(facts.network_kind)?,
        ..Snapshot::default()
    })
}
