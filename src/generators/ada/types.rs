//! The type declarations of the package spec: a record per packet, a
//! variant record per union, and a controlled `<T>_Array` per type that
//! holds its elements through access values (which also boxes members that
//! would make a record contain itself).

use std::collections::{HashMap, HashSet};

use super::naming::{arm_literal, component_type, default_value, ident, type_name};
use crate::generators::common::{Out, member_category};
use crate::ir::{Arm, Module, Packet, Union, ValueType};

/// The members (packet name, member name) and union arms (union name, arm
/// name) stored in a one-element `<T>_Array` instead of by value, because
/// the record would otherwise contain itself.
#[derive(Default)]
pub struct Boxes {
    boxed: HashSet<(String, String)>,
}

/// The type a by-value packet or union component refers to.
fn by_value(ty: &ValueType) -> Option<&str> {
    match ty {
        ValueType::Packet(n) | ValueType::Union(n) => Some(n),
        _ => None,
    }
}

/// Every by-value edge: (owner, member or arm, target type).
fn edges(module: &Module) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for p in &module.packets {
        for m in p.members.iter().filter(|m| m.array.is_none()) {
            if let Some(t) = by_value(&m.ty) {
                out.push((p.name.clone(), m.name.clone(), t.to_string()));
            }
        }
    }
    for u in &module.unions {
        for a in u.arms.iter().filter(|a| !a.is_bytes()) {
            if let Some(t) = a.ty.as_ref().and_then(by_value) {
                out.push((u.name.clone(), a.name.clone(), t.to_string()));
            }
        }
    }
    out
}

fn reaches(graph: &HashMap<&str, Vec<&str>>, from: &str, to: &str) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![from];
    while let Some(n) = stack.pop() {
        if n == to {
            return true;
        }
        if seen.insert(n) {
            stack.extend(graph.get(n).into_iter().flatten().copied());
        }
    }
    false
}

impl Boxes {
    /// Box every by-value edge that lies on a cycle.
    pub fn new(module: &Module) -> Self {
        let all = edges(module);
        let mut graph: HashMap<&str, Vec<&str>> = HashMap::new();
        for (from, _, to) in &all {
            graph.entry(from.as_str()).or_default().push(to.as_str());
        }
        let boxed = all
            .iter()
            .filter(|(from, _, to)| reaches(&graph, to, from))
            .map(|(f, m, _)| (f.clone(), m.clone()))
            .collect();
        Boxes { boxed }
    }

    pub fn member(&self, packet: &str, member: &str) -> bool {
        self.boxed.contains(&(packet.to_string(), member.to_string()))
    }

    /// The records in an order where every by-value component's type comes
    /// first (boxed components do not count).
    fn order(&self, module: &Module) -> Vec<String> {
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        for (from, m, to) in edges(module) {
            if !self.boxed.contains(&(from.clone(), m)) {
                graph.entry(from).or_default().push(to);
            }
        }
        fn visit(n: &str, graph: &HashMap<String, Vec<String>>, done: &mut HashSet<String>, order: &mut Vec<String>) {
            if !done.insert(n.to_string()) {
                return;
            }
            for t in graph.get(n).into_iter().flatten() {
                visit(t, graph, done, order);
            }
            order.push(n.to_string());
        }
        let mut done = HashSet::new();
        let mut order = Vec::new();
        for n in module.unions.iter().map(|u| &u.name).chain(module.packets.iter().map(|p| &p.name)) {
            visit(n, &graph, &mut done, &mut order);
        }
        order
    }
}

/// A component's type: boxed components are the target's `<T>_Array`.
fn component(unit: &str, ty: &ValueType, array: bool, boxed: bool) -> String {
    component_type(unit, ty, array || boxed)
}

/// The type of an arm's component.
fn arm_type(unit: &str, arm: &Arm, ty: &ValueType, boxed: bool) -> String {
    if arm.is_bytes() { "Pb_Bytes".into() } else { component(unit, ty, false, boxed) }
}

fn declare_union(out: &mut Out, unit: &str, u: &Union, boxes: &Boxes) {
    let name = type_name(&u.name);
    out.line(format!("--  Union {}: Kind says which arm it holds.", u.name));
    out.line(format!("type {} (Kind : {}_Kind := {}) is record", name, name, arm_literal(&u.name, &u.arms[0])));
    out.push();
    out.line("case Kind is");
    out.push();
    for arm in &u.arms {
        out.line(format!("when {} =>", arm_literal(&u.name, arm)));
        out.push();
        match &arm.ty {
            Some(t) => out.line(format!(
                "{} : {};",
                ident(&arm.name),
                arm_type(unit, arm, t, boxes.member(&u.name, &arm.name))
            )),
            None => out.line("null;"),
        }
        out.pop();
    }
    out.pop();
    out.line("end case;");
    out.pop();
    out.line("end record;");
}

fn declare_record(out: &mut Out, unit: &str, p: &Packet, boxes: &Boxes) {
    let name = type_name(&p.name);
    if p.members.is_empty() {
        out.line(format!("type {} is null record;", name));
        return;
    }
    out.line(format!("type {} is record", name));
    out.push();
    for m in &p.members {
        if let Some(cat) = member_category(m) {
            out.line(format!("--  Values from {}.", cat));
        }
        let ty = component(unit, &m.ty, m.array.is_some(), boxes.member(&p.name, &m.name));
        match default_value(m) {
            Some(d) => out.line(format!("{} : {} := {};", ident(&m.name), ty, d)),
            None => out.line(format!("{} : {};", ident(&m.name), ty)),
        }
    }
    out.pop();
    out.line("end record;");
}

/// Every type name: unions, then packets.
pub fn type_names(module: &Module) -> Vec<String> {
    module.unions.iter().map(|u| type_name(&u.name)).chain(module.packets.iter().map(|p| type_name(&p.name))).collect()
}

/// The type declarations of the spec.
pub fn declare_types(out: &mut Out, unit: &str, module: &Module, boxes: &Boxes) {
    let names = type_names(module);
    if names.is_empty() {
        return;
    }
    out.line("");
    out.line("--  Arrays of packets hold their elements through access values;");
    out.line("--  assignment copies them and finalization frees them.");
    for t in &names {
        out.line("");
        out.line(format!("type {};", t));
        out.line(format!("type {}_Access is access {};", t, t));
        out.line(format!("type {}_Access_Array is array (Natural range <>) of {}_Access;", t, t));
        out.line(format!("type {}_Access_Array_Access is access {}_Access_Array;", t, t));
        out.line(format!("type {}_Array is new Ada.Finalization.Controlled with record", t));
        out.push();
        out.line(format!("Items : {}_Access_Array_Access;", t));
        out.line("Len   : Natural := 0;");
        out.pop();
        out.line("end record;");
        out.line(format!("overriding procedure Adjust (A : in out {}_Array);", t));
        out.line(format!("overriding procedure Finalize (A : in out {}_Array);", t));
    }
    for u in &module.unions {
        let lits: Vec<String> = u.arms.iter().map(|a| arm_literal(&u.name, a)).collect();
        out.line("");
        out.line(format!("type {}_Kind is ({});", type_name(&u.name), lits.join(", ")));
    }
    for n in boxes.order(module) {
        out.line("");
        if let Some(u) = module.unions.iter().find(|u| u.name == n) {
            declare_union(out, unit, u, boxes);
        } else if let Some(p) = module.packets.iter().find(|p| p.name == n) {
            declare_record(out, unit, p, boxes);
        }
    }
    for t in &names {
        out.line("");
        out.line(format!("function Length (A : {}_Array'Class) return Natural;", t));
        out.line("--  The default value past the end.");
        out.line(format!("function Element (A : {}_Array'Class; I : Natural) return {};", t, t));
        out.line(format!("procedure Append (A : in out {}_Array'Class; V : {});", t, t));
        out.line(format!("procedure Clear (A : in out {}_Array'Class);", t));
        out.line(format!("function Pb_Box (V : {}) return {}_Array;", t, t));
    }
}

/// The bodies of the array operations.
pub fn implement_arrays(out: &mut Out, module: &Module) {
    for t in type_names(module) {
        out.line("");
        out.line(format!("procedure Pb_Free is new Ada.Unchecked_Deallocation ({}, {}_Access);", t, t));
        out.line(format!(
            "procedure Pb_Free is new Ada.Unchecked_Deallocation ({}_Access_Array, {}_Access_Array_Access);",
            t, t
        ));
        out.line("");
        out.line(format!("function Length (A : {}_Array'Class) return Natural is (A.Len);", t));
        out.line("");
        out.line(format!("function Element (A : {}_Array'Class; I : Natural) return {} is", t, t));
        out.line("begin");
        out.push();
        out.line("if A.Items = null or else I >= A.Len then");
        out.line(format!("   return D : {};", t));
        out.line("end if;");
        out.line("return A.Items (I).all;");
        out.pop();
        out.line("end Element;");
        out.line("");
        out.line(format!("procedure Append (A : in out {}_Array'Class; V : {}) is", t, t));
        out.line(format!("   Old : {}_Access_Array_Access := A.Items;", t));
        out.line("begin");
        out.push();
        out.line("if Old = null or else A.Len = Old'Length then");
        out.line(format!("   A.Items := new {}_Access_Array (0 .. 2 * A.Len + 3);", t));
        out.line("   if Old /= null then");
        out.line("      A.Items (0 .. A.Len - 1) := Old (0 .. A.Len - 1);");
        out.line("      Pb_Free (Old);");
        out.line("   end if;");
        out.line("end if;");
        out.line(format!("A.Items (A.Len) := new {}'(V);", t));
        out.line("A.Len := A.Len + 1;");
        out.pop();
        out.line("end Append;");
        out.line("");
        out.line(format!("procedure Clear (A : in out {}_Array'Class) is", t));
        out.line("begin");
        out.push();
        out.line("if A.Items /= null then");
        out.line("   for I in 0 .. A.Len - 1 loop");
        out.line("      Pb_Free (A.Items (I));");
        out.line("   end loop;");
        out.line("   Pb_Free (A.Items);");
        out.line("end if;");
        out.line("A.Len := 0;");
        out.pop();
        out.line("end Clear;");
        out.line("");
        out.line(format!("overriding procedure Adjust (A : in out {}_Array) is", t));
        out.line(format!("   Old : constant {}_Access_Array_Access := A.Items;", t));
        out.line("begin");
        out.push();
        out.line("if Old /= null then");
        out.line(format!("   A.Items := new {}_Access_Array'(Old'Range => null);", t));
        out.line("   for I in 0 .. A.Len - 1 loop");
        out.line(format!("      A.Items (I) := new {}'(Old (I).all);", t));
        out.line("   end loop;");
        out.line("end if;");
        out.pop();
        out.line("end Adjust;");
        out.line("");
        out.line(format!("overriding procedure Finalize (A : in out {}_Array) is", t));
        out.line("begin");
        out.line("   Clear (A);");
        out.line("end Finalize;");
        out.line("");
        out.line(format!("function Pb_Box (V : {}) return {}_Array is", t, t));
        out.line("begin");
        out.line(format!("   return A : {}_Array do", t));
        out.line("      Append (A, V);");
        out.line("   end return;");
        out.line("end Pb_Box;");
    }
}
