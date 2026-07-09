//
// Copyright 2026, UNSW
// Copyright 2026, ANU
//
// SPDX-License-Identifier: BSD-2-Clause
//
// Adapted from the Fiducia Project, ANU.
//

//! This module is responsible for producing a Graphviz dot file representing the objects
//! allocated by the System Description Format (SDF).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Write};

use crate::sdf::{Channel, ProtectionDomain, SysMapPerms, SysMemoryRegion, SystemDescription};

const BLUE : &'static str = "#59e";
const FIREBRICK : &'static str = "#B22222";

const GREY : &'static str = "#777777";

const LIGHT_CELL : &'static str = "#e0e0e0";
const DARK_CELL  : &'static str = "#b0b0b0";


pub fn to_dot(sd : &SystemDescription) -> Result<String, fmt::Error> {
  let mut out = String::new();
  let mut indent = 0;

  let mr_sizes : BTreeMap<&str, u64> = {
    sd.memory_regions.iter().map(|mr| (mr.name.as_str(), mr.size)).collect()
  };

  writeln!(out,
r#"{:indent$}digraph system {{
    rankdir=LR;
    graph [splines=line, ranksep=1.5, nodesep=0.6];
    fontname="DejaVu Sans";
    node  [fontsize=12, fontname="DejaVu Sans"];
    edge  [fontsize=10, fontname="DejaVu Sans"];"#,
    ""
  )?;
  writeln!(out)?;

  writeln!(out, "{:indent$}subgraph cluster {{", "")?;

  // start memory cluster
  indent += 4;

  writeln!(out, "{:indent$}penwidth=0;", "")?;

  writeln!(out, "{:indent$}subgraph cluster_virt_memory {{", "")?;

  // start virt memory cluster
  indent += 4;

  writeln!(out,
    r#"{:indent$}label="Virtual Memory"; penwidth="1pt";"#,
  "")?;
  // Virtual memory mappings by protection domain
  for pd in sd.protection_domains.iter() {
    write_pd_vaddrs(&mut out, indent, pd, &mr_sizes)?;
  }

  // end virt memory cluster
  indent -= 4;

  writeln!(out, "{:indent$}}}", "")?;
  writeln!(out)?;

  write_memory_regions(&mut out, indent, &sd.memory_regions)?;

  // Write mappings from vaddrs to memory regions
  writeln!(out, "{:indent$}// Mappings", "")?;
  for pd in sd.protection_domains.iter() {
    for mapping in pd.maps.iter() {
      let port = mapping_port(&pd.name, &mapping.mr);
      let style = if mapping.perms & SysMapPerms::Write as u8 == 0 { "dashed" } else { "solid" };
      writeln!(
        out,
        r#"{:indent$}"vm_{}":{port} -> phys_memory:"{}" [style={style}, color="{GREY}", arrowsize=0.7];"#,
        "",
        pd.name,
        mapping.mr,
      )?;
    }
  }

  // end memory cluster
  indent -= 4;
  writeln!(out, "{:indent$}}}", "")?;
  writeln!(out)?;

  writeln!(out, "{:indent$}// Channels and Fault Handling", "")?;
  write_channels_and_hierarchy(&mut out, indent, &sd.protection_domains, &sd.channels)?;

  // end overall graph
  writeln!(out, "{:indent$}}}", "")?;

  Ok(out)
}

fn write_pd_vaddrs(
  out : &mut String,
  mut indent : usize,
  pd : &ProtectionDomain,
  _mr_sizes : &BTreeMap<&str, u64>,
) -> fmt::Result
{
  let mut mappings = pd.maps.clone();
  // sort in _descending_ order
  mappings.sort_by(|ma, mb| ma.vaddr.cmp(&mb.vaddr).reverse());

  let elfname = {
    if let Ok(path) = str::from_utf8(pd.program_image.as_os_str().as_encoded_bytes()) {
      path.to_string()
    } else {
      format!("{:?}", pd.program_image)
    }
  };

  writeln!(out, "")?;
  writeln!(out, "{:indent$}// PD: {}", "", pd.name)?;
  writeln!(out,
    r#"{:indent$}"vm_{}" [shape=plain, label=<"#,
    "",
    pd.name
  )?;

  // Table
  indent += 4;
  writeln!(out,
    r#"{:indent$}<table border="0" cellborder="0" cellspacing="0" cellpadding="0">"#,
    ""
  )?;

  // Header Row
  writeln!(out,
    r#"{:indent$}<tr><td bgcolor="{BLUE}" align="center" cellpadding="4" colspan="3">"#,
    ""
  )?;
  indent += 4;
  writeln!(out,
    r#"{:indent$}<font color="white"><b>{}</b></font>"#,
    "",
    pd.name
  )?;
  indent -= 4;
  writeln!(out, "{:indent$}</td></tr>", "")?;

  // elf file
  // TODO: should probably be (rx), but how to tell?
  writeln!(out,
    r#"{:indent$}<tr><td bgcolor="{DARK_CELL}" align="left" cellpadding="4" colspan="3">{}</td></tr>"#,
    "",
    &elfname,
  )?;
  // Memory mappings for each protection domain
  for (i, mapping) in mappings.iter().enumerate() {
    // Content: memory mapped regions, with name and permissions
    let port = mapping_port(&pd.name, &mapping.mr);
    let bgcolor = if i % 2 == 0 { LIGHT_CELL } else { DARK_CELL };

    let mut perms = String::new();
    if mapping.perms & SysMapPerms::Read as u8 != 0 {
      perms.push('r');
    }
    if mapping.perms & SysMapPerms::Write as u8 != 0 {
      perms.push('w');
    }
    if mapping.perms & SysMapPerms::Execute as u8 != 0 {
      perms.push('x');
    }

    writeln!(out, r#"{:indent$}<tr>"#, "")?;
    indent += 4;
    writeln!(out,
      r#"{:indent$}<td bgcolor="{bgcolor}" align="left" cellpadding="4">{}</td>"#,
      "",
      &mapping.mr
    )?;
    writeln!(out,
      r#"{:indent$}<td bgcolor="{bgcolor}" align="right" cellpadding="4">{:#X}</td>"#,
      "",
      mapping.vaddr
    )?;
    writeln!(out,
      r#"{:indent$}<td port="{port}" bgcolor="{bgcolor}" align="left" cellpadding="4">{}</td>"#,
      "",
      perms,
    )?;
    indent -= 4;
    writeln!(out, r#"{:indent$}</tr>"#, "")?;
  }

  // close table
  writeln!(out, "{:indent$}</table>>];", "")?;

  Ok(())
}

fn write_memory_regions(
  out : &mut String,
  mut indent : usize,
  mrs : &[SysMemoryRegion],
) -> fmt::Result
{
  writeln!(out, "{:indent$}subgraph cluster_phys_memory {{", "")?;

  indent += 4;

  writeln!(out, r#"{:indent$}label="Physical Memory"; penwidth="1pt";"#, "")?;
  writeln!(out)?;

  // Physical Memory Table

  writeln!(out, r#"{:indent$}phys_memory [shape=plain, label=<"#, "")?;
  indent += 4;

  writeln!(out,
    r#"{:indent$}<table border="0" cellborder="0" cellspacing="0">"#,
    ""
  )?;
  indent += 4;

  let mut mrs = mrs.to_vec();
  mrs.sort_by_key(|mr| mr.paddr());

  for (i, mr) in mrs.iter().enumerate() {
    let size_str = fmt_bytes(mr.size);
    let phys = {
      mr.paddr().map_or(String::new(), |a| format!("{:#X}", a))
    };

    let bgcolor = if i % 2 == 0 { LIGHT_CELL } else { DARK_CELL };

    writeln!(out, r#"{:indent$}<tr>"#, "")?;
    indent += 4;

    writeln!(out,
      r#"{:indent$}<td port="{}" bgcolor="{bgcolor}" align="left" cellpadding="4">{}</td>"#,
      "",
      mr.name,
      mr.name,
    )?;

    // addr
    writeln!(out, r#"{:indent$}<td bgcolor="{bgcolor}" align="right" cellpadding="4">{}</td>"#, "", phys)?;

    // size
    writeln!(out, r#"{:indent$}<td bgcolor="{bgcolor}" align="left" cellpadding="4">{}</td>"#, "", size_str)?;

    indent -= 4;
    writeln!(out, "{:indent$}</tr>", "")?;
  }

  // close table
  indent -= 4;
  writeln!(out, "{:indent$}</table>>];", "")?;

  indent -= 4;
  writeln!(out, "{:indent$}}}", "")?;
  writeln!(out)?;


  Ok(())
}


fn write_pd_channels(
  out : &mut String,
  mut indent : usize,
  _pd_id : usize,
  pd : &ProtectionDomain,
  _channels : &BTreeSet<&Channel>,
) -> fmt::Result
{
  let mut mappings = pd.maps.clone();
  // sort in _descending_ order
  mappings.sort_by(|ma, mb| ma.vaddr.cmp(&mb.vaddr).reverse());

  writeln!(out, "")?;
  writeln!(out, "{:indent$}// PD: {}", "", pd.name)?;
  writeln!(out,
    r#"{:indent$}"ch_{}" [shape=plain, label=<"#,
    "",
    pd.name
  )?;

  // Table
  indent += 4;
  writeln!(out,
    r#"{:indent$}<table border="0" cellborder="0" cellspacing="0" cellpadding="0">"#,
    ""
  )?;

  // Header Row
  writeln!(out,
    r#"{:indent$}<tr><td bgcolor="{BLUE}" align="center" cellpadding="4">"#,
    ""
  )?;
  indent += 4;
  writeln!(out,
    r#"{:indent$}<font color="white"><b>{}</b> pri={}</font>"#,
    "",
    pd.name,
    pd.priority
  )?;
  indent -= 4;
  writeln!(out, "{:indent$}</td></tr>", "")?;

  // close table
  writeln!(out, "{:indent$}</table>>];", "")?;

  Ok(())
}

fn write_channels_and_hierarchy(
  out : &mut String,
  mut indent : usize,
  protection_domains : &[ProtectionDomain],
  channels : &[Channel],
) -> fmt::Result
{
  // TODO: pd.irqs

  if channels.is_empty() { return Ok(()); }

  let mut chan_by_pd = BTreeMap::new();
  let mut chan_degree = BTreeMap::new();

  for ch in channels {
    *chan_degree.entry(ch.end_a.pd).or_insert(0usize) += 1;
    *chan_degree.entry(ch.end_b.pd).or_insert(0usize) += 1;

    chan_by_pd.entry(ch.end_a.pd).or_insert(BTreeSet::new()).insert(ch);
    chan_by_pd.entry(ch.end_b.pd).or_insert(BTreeSet::new()).insert(ch);
  }

  let min_degree_pd = {
    chan_degree.iter().min_by_key(|(_, d)| **d).expect("safe by prior test")
  };

  let mut seen  = BTreeSet::new();
  let mut fringe = VecDeque::new();
  fringe.push_back(*min_degree_pd.0);

  writeln!(out, "{:indent$}subgraph cluster_channels {{", "")?;
  // start channel cluster
  indent += 4;
  writeln!(out, r#"{:indent$}penwidth=0; penwidth="1pt";"#, "")?;

  // Write out channels by pd
  while let Some(pd_id) = fringe.pop_front() {
    if seen.contains(&pd_id) { continue; }

    let chans = {
      chan_by_pd.get(&pd_id).expect("safe by construction of chan_by_pd")
    };

    write_pd_channels(out, indent, pd_id, &protection_domains[pd_id], chans)?;

    for ch in chans {
      // DATA INV: ch.end_a.pd != ch.end_b.pd
      let other_pd = if ch.end_a.pd != pd_id { ch.end_a.pd } else { ch.end_b.pd };
      fringe.push_back(other_pd);
    }

    seen.insert(pd_id);
  }

  // Connect them together
  for ch in channels {
    let pd_a = &protection_domains[ch.end_a.pd];
    let pd_b = &protection_domains[ch.end_b.pd];

    let pp_a = if ch.end_a.pp { " (pp)" } else { "" };
    let pp_b = if ch.end_b.pp { " (pp)" } else { "" };

    writeln!(out,
      r#"{:indent$}"ch_{}" -> "ch_{}" [style=solid, dir=both, color="{GREY}", penwidth=1.5, constraint=false, headlabel="{}{}", taillabel="{}{}", labeldistance="3.5"];"#,
      "",
      pd_a.name,
      pd_b.name,
      ch.end_a.id, pp_a,
      ch.end_b.id, pp_b,
    )?;
  }
  writeln!(out)?;

  writeln!(out, "{:indent$}// child/parent relation", "")?;
  for pd in protection_domains.iter() {
    if let Some(i) = pd.parent {
      let parent = {
        protection_domains.get(i).expect("parent indexes malformed")
      };

      writeln!(
        out,
        r#"{:indent$}"ch_{}" -> "ch_{}" [color="{FIREBRICK}", arrowsize=0.7];"#,
        "",
        pd.name,
        parent.name,
      )?;
    }
  }

  // end channel cluster
  indent -= 4;
  writeln!(out, "{:indent$}}}", "")?;

  writeln!(out)?;

  Ok(())
}


/// Generate a DOT port name for each protection domain's mapping to a memory region.
fn mapping_port(pd_name: &str, mr_name: &str) -> String {
  format!(
    "m_{}_{}",
    pd_name.replace('-', "_"),
    mr_name.replace('-', "_")
  )
}

/*
fn slot_port(pd_name: &str, slot: usize) -> String {
  format!("s_{}_{}", pd_name.replace('-', "_"), slot)
}
*/

const MEBIBYTES : u64 = 0x100000;
const KIBIBYTES : u64 = 0x400;

#[allow(clippy::cast_precision_loss)]
fn fmt_bytes(n: u64) -> String {
  if n >= MEBIBYTES {
    format!("{:.1}MiB", n as f64 / MEBIBYTES as f64)
  } else if n >= KIBIBYTES {
    format!("{:.1}KiB", n as f64 / KIBIBYTES as f64)
  } else {
    format!("{n} B")
  }
}
