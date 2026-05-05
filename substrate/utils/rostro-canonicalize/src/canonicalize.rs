// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Rostro Foundation contributors

// Structural canonicalization of metadata types.
//
// Walks a `scale_info::PortableRegistry` type and produces a deterministic
// whitespace-free string representation. Used by both the runtime side
// (`pallet-rostro-type-registry`'s `build.rs`, indirectly) and the client
// recognizer.
//
// Format rules (must match byte-for-byte across both ends):
// - whitespace-free
// - struct fields and enum variants alphabetized
// - primitives: `u8`, `u32`, `u64`, `u128`, `bool`, `str`, ...
// - arrays: `[T;N]`
// - sequences: `Vec<T>`
// - compact: `Compact<T>`
// - tuples: `(T1,T2,...)` or `()` for unit
// - structs: `struct{a:T,b:T}` (named fields, sorted by name)
// - enums: `enum{Unit,Tuple(T),Named{a:T}}` (variants sorted by name)
// - newtype unwrap: a single-field composite is canonicalized as its inner
//   type — the role marker carries the semantic distinction
//
// This file is shared between `lib.rs` (via `mod`) and `build.rs` (via
// `include!`) so the build-time deriver and the runtime recognizer use
// identical logic. Use regular `//` comments only — `//!` inner doc
// comments are not valid mid-file and `include!` puts this content into
// the middle of `build.rs`.

use alloc::{
	string::{String, ToString},
	vec::Vec,
};
use scale_info::{form::PortableForm, PortableRegistry, TypeDef, TypeDefPrimitive};

/// Maximum depth of type-tree recursion the canonicalizer will accept.
/// Prevents adversarial metadata from forcing unbounded recursion.
pub const MAX_CANONICALIZE_DEPTH: u32 = 32;

/// Errors the canonicalizer can produce. Each is a structural property of the
/// input metadata, not a runtime error — types prove shape, not validity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalizeError {
	/// Type id was not present in the registry.
	UnknownTypeId(u32),
	/// Recursion exceeded `MAX_CANONICALIZE_DEPTH`.
	DepthLimitExceeded,
	/// scale-info BitSequence types are not part of the v0 grammar.
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
	let ty = registry.resolve(id).ok_or(CanonicalizeError::UnknownTypeId(id))?;

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

/// Detect the "newtype wrapper" pattern. A single-field composite (tuple
/// struct or single-named-field struct) is treated as transparent — its
/// canonical_def is the inner type's canonical_def. The role marker carries
/// the semantic distinction.
pub fn newtype_inner_id(td: &TypeDef<PortableForm>) -> Option<u32> {
	if let TypeDef::Composite(c) = td {
		if c.fields.len() == 1 {
			return Some(c.fields[0].ty.id);
		}
	}
	None
}

/// Name of a primitive type in the canonical_def grammar.
pub fn primitive_name(p: &TypeDefPrimitive) -> &'static str {
	use TypeDefPrimitive::*;
	match p {
		Bool => "bool",
		Char => "char",
		Str => "str",
		U8 => "u8",
		U16 => "u16",
		U32 => "u32",
		U64 => "u64",
		U128 => "u128",
		U256 => "u256",
		I8 => "i8",
		I16 => "i16",
		I32 => "i32",
		I64 => "i64",
		I128 => "i128",
		I256 => "i256",
	}
}
