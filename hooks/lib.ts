export type Secrets = Record<string, string>

export const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/

const LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/

function unquote(raw: string): string {
  const v = raw.trim()
  if (v.startsWith("'") && v.endsWith("'") && v.length >= 2)
    return v.slice(1, -1).replaceAll(`'\\''`, "'")
  if (v.startsWith('"') && v.endsWith('"') && v.length >= 2)
    return v.slice(1, -1).replace(/\\(["\\$`])/g, '$1')
  return v
}

export function parse(text: string): Secrets {
  const out: Secrets = {}
  for (const line of text.split('\n')) {
    if (line.trim().startsWith('#')) continue
    const m = LINE.exec(line)
    if (m?.[1] !== undefined && m[2] !== undefined) out[m[1]] = unquote(m[2])
  }
  return out
}

export function serialize(secrets: Secrets): string {
  const lines = Object.keys(secrets)
    .sort()
    .map(k => `export ${k}='${(secrets[k] ?? '').replaceAll("'", `'\\''`)}'`)
  return `${lines.join('\n')}\n`
}

const sq = (s: string) => `'${s.replaceAll("'", `'\\''`)}'`

// Os nomes conhecidos que aparecem como palavra no comando ($TOKEN, ${TOKEN}, export TOKEN).
export function cited(command: string, names: string[]): string[] {
  return names.filter(n => new RegExp(`(^|[^A-Za-z0-9_])${n}($|[^A-Za-z0-9_])`).test(command))
}

export function wrap(command: string, loader: string, names: string[]): string {
  return `. ${sq(loader)} ${names.join(' ')}\n${command}`
}

// Valores curtos demais mascarariam texto comum.
const MIN_MASK = 4

export function mask(text: string, secrets: Secrets): string {
  let out = text
  const byLength = Object.entries(secrets).sort((a, b) => b[1].length - a[1].length)
  for (const [k, v] of byLength) if (v.length >= MIN_MASK) out = out.split(v).join(`«${k}»`)
  return out
}

export function maskDeep<T>(value: T, secrets: Secrets): T {
  if (typeof value === 'string') return mask(value, secrets) as T
  if (Array.isArray(value)) return value.map(v => maskDeep(v, secrets)) as T
  if (value !== null && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, maskDeep(v, secrets)]),
    ) as T
  return value
}

export const PREFIX = 'segredos:'

export type KernelKey = { id: number; name: string; timeout: string }

// Linha de /proc/keys: id(hex) flags uso timeout perm uid gid tipo descrição: resto
export function parseProcKeys(text: string): KernelKey[] {
  const out: KernelKey[] = []
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/)
    const desc = f[8]
    if (f.length < 9 || f[7] !== 'user' || desc === undefined || !desc.startsWith(PREFIX)) continue
    const timeout = f[3] ?? ''
    if (timeout === 'expd' || (f[1] ?? '').includes('R')) continue
    const name = desc.slice(PREFIX.length).replace(/:$/, '')
    if (NAME.test(name)) out.push({ id: parseInt(f[0] ?? '', 16), name, timeout })
  }
  return out
}

const UNIT: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }

// "90m", "8h", "7d", "1h30m" → segundos; vazio → undefined (permanente); inválido → NaN.
export function parseTtl(raw: string): number | undefined {
  const t = raw.trim().toLowerCase()
  if (t === '') return undefined
  let total = 0
  const re = /(\d+)\s*([smhdw])/gy
  let m: RegExpExecArray | null
  let end = 0
  while ((m = re.exec(t)) !== null) {
    total += Number(m[1]) * (UNIT[m[2] ?? ''] ?? 0)
    end = re.lastIndex
  }
  return end === t.length && total > 0 ? total : NaN
}
