//!
//! Wrapper for XmlSec Signature Context
//!
use crate::bindings;

use super::XmlDocument;
use super::XmlSecError;
use super::XmlSecKey;
use super::XmlSecResult;

use std::os::raw::c_uchar;
use std::ptr::{null, null_mut};

/// Signature signing/veryfying context
pub struct XmlSecDecryptContext {
    ctx: *mut bindings::xmlSecEncCtx,
}

impl XmlSecDecryptContext {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> XmlSecResult<Self> {
        super::xmlsec_internal::guarantee_xmlsec_init()?;

        let ctx: *mut bindings::_xmlSecEncCtx = unsafe { bindings::xmlSecEncCtxCreate(null_mut()) };

        if ctx.is_null() {
            return Err(XmlSecError::ContextInitError);
        }

        Ok(Self { ctx })
    }

    /// Sets the key to use for decryption. In case a key had
    /// already been set, the latter one gets released in the optional return.
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey> {
        let mut old = None;

        unsafe {
            if !(*self.ctx).encKey.is_null() {
                old = Some(XmlSecKey::from_ptr((*self.ctx).encKey));
            }

            (*self.ctx).encKey = XmlSecKey::leak(key);
        }

        old
    }

    /// Releases a currently set key returning `Some(key)` or None otherwise.
    #[allow(unused)]
    pub fn release_key(&mut self) -> Option<XmlSecKey> {
        unsafe {
            if (*self.ctx).encKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr((*self.ctx).encKey);

                (*self.ctx).encKey = null_mut();

                Some(key)
            }
        }
    }

    pub fn decrypt_document(&self, doc: &libxml::tree::Node) -> XmlSecResult<()> {
        self.key_is_set()?;

        let node_ptr = doc.node_ptr() as *mut bindings::xmlNode;

        let encnode = find_encNode(node_ptr)?;
        self.decrypt_node_raw(encnode)
    }
}

impl XmlSecDecryptContext {
    fn key_is_set(&self) -> XmlSecResult<()> {
        unsafe {
            if !(*self.ctx).encKey.is_null() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    fn decrypt_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<()> {
        let rc = unsafe { bindings::xmlSecEncCtxDecrypt(self.ctx, node) };

        if rc < 0 {
            Err(XmlSecError::DecryptionFailed)
        } else {
            Ok(())
        }
    }
}

impl Drop for XmlSecDecryptContext {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecEncCtxDestroy(self.ctx) };
    }
}

fn find_encNode(tree: *mut bindings::xmlNode) -> XmlSecResult<*mut bindings::xmlNode> {
    let signode = unsafe {
        bindings::xmlSecFindNode(
            tree,
            &bindings::xmlSecNodeEncryptedData as *const c_uchar,
            &bindings::xmlSecEncNs as *const c_uchar,
        )
    };

    if signode.is_null() {
        return Err(XmlSecError::NodeNotFound);
    }

    Ok(signode)
}
