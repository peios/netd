//! Borrow Rust configuration into C layouts for one synchronous call.

use std::marker::PhantomData;
use std::ptr;

use netd_abi as abi;

use crate::{Error, InterfaceFacts, RawKey, RawValue, invalid, span};

const MAX_KEY_DEPTH: usize = 128;
const MAX_ITEMS: usize = 65_536;

#[derive(Default)]
pub(crate) struct Input<'a> {
    keys: Vec<Box<[abi::Key]>>,
    values: Vec<Box<[abi::Value]>>,
    lists: Vec<Box<[abi::Bytes]>>,
    items: usize,
    borrowed: PhantomData<&'a RawKey>,
}

impl<'a> Input<'a> {
    pub(crate) fn tree(&mut self, root: Option<&'a RawKey>) -> Result<*const abi::Key, Error> {
        let Some(root) = root else {
            return Ok(ptr::null());
        };
        let view = self.key(root, 0)?;
        let keys: Box<[_]> = vec![view].into();
        let pointer = keys.as_ptr();
        self.keys.push(keys);
        Ok(pointer)
    }

    fn count(&mut self, count: usize) -> Result<(), Error> {
        self.items = self
            .items
            .checked_add(count)
            .filter(|total| *total <= MAX_ITEMS)
            .ok_or_else(|| invalid("configuration exceeds 65536 items"))?;
        Ok(())
    }

    fn value(&mut self, name: &'a str, value: &'a RawValue) -> Result<abi::Value, Error> {
        let mut out = abi::Value {
            name: span(name.as_bytes()),
            kind: 0,
            integer: 0,
            text: span(&[]),
            list: abi::Strings {
                data: ptr::null(),
                len: 0,
            },
        };
        match value {
            RawValue::Other => (),
            RawValue::Int(integer) => {
                out.kind = 1;
                out.integer = *integer;
            }
            RawValue::Str(text) => {
                out.kind = 2;
                out.text = span(text.as_bytes());
            }
            RawValue::List(list) => {
                self.count(list.len())?;
                let views: Box<[_]> = list.iter().map(|text| span(text.as_bytes())).collect();
                out.kind = 3;
                out.list = abi::Strings {
                    data: views.as_ptr(),
                    len: views.len(),
                };
                self.lists.push(views);
            }
        }
        Ok(out)
    }

    fn key(&mut self, key: &'a RawKey, depth: usize) -> Result<abi::Key, Error> {
        if depth >= MAX_KEY_DEPTH {
            return Err(invalid("configuration exceeds 128 key levels"));
        }
        self.count(1)?;
        self.count(key.values.len())?;
        if key.children.len() > MAX_ITEMS - self.items {
            return Err(invalid("too many child keys"));
        }
        let values: Box<[_]> = key
            .values
            .iter()
            .map(|(name, value)| self.value(name, value))
            .collect::<Result<_, _>>()?;
        let children: Box<[_]> = key
            .children
            .iter()
            .map(|child| self.key(child, depth + 1))
            .collect::<Result<_, _>>()?;
        let view = abi::Key {
            name: span(key.name.as_bytes()),
            values: values.as_ptr(),
            value_count: values.len(),
            children: children.as_ptr(),
            child_count: children.len(),
        };
        self.values.push(values);
        self.keys.push(children);
        Ok(view)
    }
}

fn optional(value: Option<&str>) -> abi::Bytes {
    value.map_or(
        abi::Bytes {
            data: ptr::null(),
            len: 0,
        },
        |text| span(text.as_bytes()),
    )
}

pub(crate) fn facts(value: &InterfaceFacts) -> abi::Facts {
    abi::Facts {
        interface: optional(value.interface.as_deref()),
        interface_kind: optional(value.interface_kind.as_deref()),
        interface_id: optional(value.interface_id.as_deref()),
        interface_mac: value.interface_mac.as_ref().map_or(
            abi::Bytes {
                data: ptr::null(),
                len: 0,
            },
            |mac| span(mac),
        ),
        interface_path: optional(value.interface_path.as_deref()),
        interface_driver: optional(value.interface_driver.as_deref()),
        network_id: optional(value.network_id.as_deref()),
        network_name: optional(value.network_name.as_deref()),
        network_trust: optional(value.network_trust.as_deref()),
        network_kind: optional(value.network_kind.as_deref()),
    }
}
