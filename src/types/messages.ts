// 与 Rust 侧 serde camelCase 输出对齐的类型

export interface PacketRow {
  index: number
  frameNumber: number
  tsUs: number
  relUs: number
  src: string
  dst: string
  direction: string
  msgType: string
  topic: string
  topicComplete: boolean
  outerType: string
  anyType: string
  deviceId: string
  summary: string
  rid: number | null
  pairIndex: number | null
  rttMs: number | null
  payloadLen: number
  warnings: string[]
}

export interface ProtoFieldNode {
  name: string
  /** message / repeated / map / scalar / enum / bytes / timestamp / unknown / error */
  kind: string
  typeName: string
  valueLabel: string
  numeric: number | null
  hex: string | null
  hexTotal: number | null
  index: number | null
  children: ProtoFieldNode[]
}

export interface Kv {
  key: string
  value: string
}

export interface DetailData {
  zenohFields: Kv[]
  protoTree: ProtoFieldNode | null
  hexLines: string[]
}

export interface Stats {
  total: number
  byType: [string, number][]
  byTopic: [string, number][]
  devices: string[]
  tsFirst: number | null
  tsLast: number | null
  sessions: string[]
}

export interface ParseResult {
  rows: PacketRow[]
  warnings: string[]
}

export interface InterfaceInfo {
  name: string
  desc: string
  /** Windows 连接别名（如 "以太网"、"WLAN"） */
  alias: string
  addresses: string[]
}

export type LiveEvent =
  | { kind: 'rows'; rows: PacketRow[]; updates: PacketRow[]; total: number }
  | { kind: 'error'; message: string }

export interface ZenohField {
  key: string
  value: string
}

// 工具：时间格式化
export function fmtAbsTime(tsUs: number): string {
  const d = new Date(tsUs / 1000)
  const p = (n: number, w = 2) => String(n).padStart(w, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}${p(Math.floor((tsUs % 1000) / 100))}`
}

export function fmtRelTime(relUs: number): string {
  const sign = relUs < 0 ? '-' : '+'
  const abs = Math.abs(relUs)
  if (abs < 1000) return `${sign}${abs}µs`
  if (abs < 1_000_000) return `${sign}${(abs / 1000).toFixed(3)}ms`
  return `${sign}${(abs / 1_000_000).toFixed(6)}s`
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}
