// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

//! Canonicalize a metadata type into the deterministic structural string
//! the pallet hashes.
//!
//! The pallet stores hand-written canonical_def strings (e.g. `[u8;32]`,
//! `enum{Immortal,Mortal{period:u64,phase:u64}}`). For client-side
//! recognition we walk the metadata's `PortableRegistry` and produce the
//! same string for any structurally-equivalent type.
//!
//! Format rules (must match the pallet exactly):
//! - whitespace-free
//! - struct/enum fields and variants alphabetized
//! - primitive type names: `u8`, `u32`, `u64`, `u128`, `bool`, `str`, ...
//! - arrays: `[T;N]`
//! - sequences: `Vec<T>`
//! - compact: `Compact<T>`
//! - tuples: `(T1,T2,...)` or `()` for unit
//! - structs: `struct{a:T,b:T}` (named fields, sorted by name)
//! - enums: `enum{Unit,Tuple(T),Named{a:T}}` (variants sorted by name)
//! - newtype unwrap: a single-field composite is canonicalized as its inner
//!   type — the role marker carries the semantic distinction
//!
//! The newtype-unwrap rule is what makes `pub struct AccountId32([u8;32])`
//! canonicalize to `[u8;32]`, matching the pallet's hand-written entry.

use crate::{newtype_inner_id, primitive_name, resolve, MAX_CANONICALIZE_DEPTH};
use scale_info::{form::PortableForm, PortableRegistry, TypeDef};

/// Errors the canonicalizer can produce. Each is a structural property of the
/// input metadata, not a runtime error — types prove shape, not validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalizeError {
	/// Type id was not present in the registry. Adversarial metadata may
	/// carry dangling ids; we reject rather than panic.
	UnknownTypeId(u32),
	/// Recursion exceeded `MAX_CANONICALIZE_DEPTH`. Adversarial metadata
	/// may try to force unbounded recursion via cyclic type references.
	DepthLimitExceeded,
	/// scale-info BitSequence types are not part of the v0 grammar. They
	/// exist in metadata for some chains; v0 leaves them out of recognition
	/// rather than guessing a canonical form.
	UnsupportedBitSequence,
}

/// Compute the canonical_def string for the given type id, resolving
/// references through the supplied registry.
pub fn canonical_def(
	id: u32,
	registry: &PortableRegistry,
) -> Result<String, CanonicalizeError> {
	let mut out = String::new();
	canonicalize_into(id, registry, &mut out, 0)?;
	Ok(out)
}

fn canonicalize_into(
	id: u32,
	registry: &PortableRegistry,
	out: &mut String,
	depth: u32,
) -> Result<(), CanonicalizeError> {
	if depth >= MAX_CANONICALIZE_DEPTH {
		return Err(CanonicalizeError::DepthLimitExceeded);
	}
	let ty = resolve(id, registry).ok_or(CanonicalizeError::UnknownTypeId(id))?;

	// Newtype unwrap before anything else — a single-field composite is
	// transparent under our grammar.
	if let Some(inner) = newtype_inner_id(&ty.type_def) {
		return canonicalize_into(inner, registry, out, depth + 1);
	}

	match &ty.type_def {
		TypeDef::Primitive(p) => {
			out.push_str(primitive_name(p));
		},
		TypeDef::Array(a) => {
			out.push('[');
			canonicalize_into(a.type_param.id, registry, out, depth + 1)?;
			out.push(';');
			out.push_str(&a.len.to_string());
			out.push(']');
		},
		TypeDef::Sequence(s) => {
			out.push_str("Vec<");
			canonicalize_into(s.type_param.id, registry, out, depth + 1)?;
			out.push('>');
		},
		TypeDef::Compact(c) => {
			out.push_str("Compact<");
			canonicalize_into(c.type_param.id, registry, out, depth + 1)?;
			out.push('>');
		},
		TypeDef::Tuple(t) => {
			out.push('(');
			for (i, field_id) in t.fields.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				canonicalize_into(field_id.id, registry, out, depth + 1)?;
			}
			out.push(')');
		},
		TypeDef::Composite(c) => {
			// Multi-field composite — render as struct{name:T,...}, sorted
			// by field name. (Single-field composites were unwrapped above.)
			out.push_str("struct{");
			let mut named: Vec<(&str, u32)> = c
				.fields
				.iter()
				.map(|f| (f.name.as_deref().unwrap_or(""), f.ty.id))
				.collect();
			named.sort_by(|a, b| a.0.cmp(b.0));
			for (i, (name, field_id)) in named.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				out.push_str(name);
				out.push(':');
				canonicalize_into(*field_id, registry, out, depth + 1)?;
			}
			out.push('}');
		},
		TypeDef::Variant(v) => {
			out.push_str("enum{");
			let mut variants: Vec<&scale_info::Variant<PortableForm>> =
				v.variants.iter().collect();
			variants.sort_by(|a, b| a.name.cmp(&b.name));
			for (i, variant) in variants.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				out.push_str(&variant.name);
				render_variant_fields(variant, registry, out, depth + 1)?;
			}
			out.push('}');
		},
		TypeDef::BitSequence(_) => {
			return Err(CanonicalizeError::UnsupportedBitSequence);
		},
	}
	Ok(())
}

fn render_variant_fields(
	variant: &scale_info::Variant<PortableForm>,
	registry: &PortableRegistry,
	out: &mut String,
	depth: u32,
) -> Result<(), CanonicalizeError> {
	if variant.fields.is_empty() {
		return Ok(());
	}
	let all_named = variant.fields.iter().all(|f| f.name.is_some());
	if all_named {
		out.push('{');
		let mut named: Vec<(&str, u32)> = variant
			.fields
			.iter()
			.map(|f| (f.name.as_deref().unwrap_or(""), f.ty.id))
			.collect();
		named.sort_by(|a, b| a.0.cmp(b.0));
		for (i, (name, id)) in named.iter().enumerate() {
			if i > 0 {
				out.push(',');
			}
			out.push_str(name);
			out.push(':');
			canonicalize_into(*id, registry, out, depth)?;
		}
		out.push('}');
	} else {
		// Tuple-style variant: positional, render in declaration order.
		// Mixing named and unnamed fields in a single variant is not
		// expressible in Rust source; we render all-unnamed as a tuple.
		out.push('(');
		for (i, field) in variant.fields.iter().enumerate() {
			if i > 0 {
				out.push(',');
			}
			canonicalize_into(field.ty.id, registry, out, depth)?;
		}
		out.push(')');
	}
	Ok(())
}
