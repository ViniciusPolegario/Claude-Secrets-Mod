import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, Timer } from 'claude-code'

import type { SecretRow } from '../types'
import { NAME, cited, mask, maskDeep, parse, parseProcKeys, parseTtl, serialize, wrap, PREFIX } from './lib.ts'
import type { Secrets } from './lib.ts'

const PANE = 'segredos'
const rowsAtom = atom({ plugin: 'segredos', key: 'rows' } as const, [])
const keyctlAtom = atom({ plugin: 'segredos', key: 'hasKeyctl' } as const, false)

// Permanentes: ~/.claude/secrets.env.gpg, cifrado para uma chave GnuPG só do mod
// (~/.claude/segredos-gnupg) protegida pela sua senha. Cifrar não pede senha; decifrar pede, numa
// janela do pinentry-gtk-2 (WSLg), e o gpg-agent a guarda na memória por IDLE sem uso, no máximo
// MAX. "trancar" esquece na hora. Um secrets.env em texto puro é absorvido no cifrado e apagado.
// Temporários: keyring do kernel (@u), que apaga ao vencer.
const IDLE = 2 * 3600
const MAX = 12 * 3600
const UID = 'segredos'
const PINENTRY = '/usr/bin/pinentry-gtk-2'
// Versão anterior (openssl + chave no keyring/DPAPI/senha): só lida para migrar.
const LEGACY_KEY = 'segredos-chave'
const PS_UNPROTECT =
  'Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); ' +
  '[Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($b,$null,"CurrentUser"))'

type Ran = { exitCode: number; stdout: string; stderr: string }

let dir = ''
let home = ''
let file = ''
let plain = ''
let loader = ''
let display: Record<string, string> = {}
// grip: keygrip da subchave de cifra; vazio enquanto não há senha.
let grip = ''
let trancado = false
let mtime = ''
let asking = false
let problem = ''
let permanent: Secrets = {}
let temporary: Secrets = {}
const valueById = new Map<number, string>()
let hasKeyctl = false
let draftName = ''
let draftTtl = ''
let draftPermanent = false
// Sem prazo digitado, o segredo é temporário por este tempo; permanente só marcando a caixa.
const DEFAULT_TTL = '8h'
let notice = ''
// ~/.claude/segredos-nomes: só os nomes e o estado, para a skill do plugin ler (sem valores).
let namesText = ''
// A linha de status só aparece depois que algum comando desta sessão recebeu um segredo.
let used = false
let ticker: Timer | undefined

const all = (): Secrets => ({ ...permanent, ...temporary })
const lastLine = (s: string) => s.trim().split('\n').at(-1) ?? ''

async function keyctl($: EngineInterface, args: string[], stdin?: string) {
  return $.process.run(['keyctl', ...args], stdin === undefined ? {} : { stdin })
}

// ask: deixa o gpg-agent abrir a janela de senha; sem ele, falha se a senha não está na memória.
async function gpg($: EngineInterface, args: string[], init: { stdin?: string; ask?: boolean } = {}): Promise<Ran> {
  const argv = ['gpg', '--homedir', home, '--batch', '--quiet', '--pinentry-mode', init.ask ? 'ask' : 'error', ...args]
  return $.process
    .run(argv, {
      env: display,
      ...(init.stdin === undefined ? {} : { stdin: init.stdin }),
      ...(init.ask ? { timeoutMs: 300_000 } : {}),
    })
    .catch(() => ({ exitCode: 1, stdout: '', stderr: 'tempo esgotado' }))
}

async function agent($: EngineInterface, command: string) {
  return $.process.run(['gpg-connect-agent', '--homedir', home, command, '/bye'], { env: display })
}

const failed = (r: Ran) =>
  /cancel/i.test(r.stderr) ? 'Cancelado.' : /bad passphrase/i.test(r.stderr) ? 'Senha errada.' : `Falhou: ${lastLine(r.stderr)}`

async function findGrip($: EngineInterface): Promise<string> {
  const got = await gpg($, ['--with-colons', '--with-keygrip', '-K', UID])
  if (got.exitCode !== 0) return ''
  return got.stdout.split('\n').filter(l => l.startsWith('grp:')).map(l => l.split(':')[9] ?? '').at(-1) ?? ''
}

// Linha "S KEYINFO <grip> D <serial> <idstr> <cached> <protection> ...".
async function keyInfo($: EngineInterface) {
  const got = await agent($, `KEYINFO ${grip}`)
  const f = got.stdout.split('\n').find(l => l.startsWith('S KEYINFO'))?.split(' ') ?? []
  return { cached: f[6] === '1', protectedByPassword: f[7] === 'P' }
}

async function stamp($: EngineInterface) {
  return (await $.process.run(['stat', '-c', '%Y', file])).stdout.trim()
}

async function load($: EngineInterface) {
  if (dir === '') {
    dir = `${(await $.env.get('HOME')) ?? '~'}/.claude`
    home = `${dir}/segredos-gnupg`
    file = `${dir}/secrets.env.gpg`
    plain = `${dir}/secrets.env`
    loader = `${$.plugin.root}/scripts/carregar.sh`
    const vars = {
      DISPLAY: await $.env.get('DISPLAY'),
      WAYLAND_DISPLAY: await $.env.get('WAYLAND_DISPLAY'),
      XDG_RUNTIME_DIR: await $.env.get('XDG_RUNTIME_DIR'),
    }
    for (const [k, v] of Object.entries(vars)) if (v !== undefined) display[k] = v
  }
  problem = ''
  hasKeyctl = (await $.process.run(['sh', '-c', 'command -v keyctl'])).exitCode === 0
  if (!hasKeyctl) problem = 'Os segredos exigem keyctl: sudo apt install keyutils'
  else if (!(await $.fs.exists(PINENTRY))) problem = 'Falta a janela de senha: sudo apt install pinentry-gtk2'

  if (grip === '' && (await $.fs.exists(home))) grip = await findGrip($)
  if (grip === '') {
    trancado = false
    permanent = {}
    if (problem === '' && (await hasLegacy($))) problem = 'Defina uma senha: seus permanentes atuais passam para o novo cofre.'
  } else {
    trancado = !(await keyInfo($)).cached
    if (trancado) {
      permanent = {}
      mtime = ''
    } else {
      const m = await stamp($)
      if (m !== mtime) {
        const got = await gpg($, ['-d', file])
        if (got.exitCode === 0) {
          permanent = parse(got.stdout)
          mtime = m
        } else trancado = true
      }
      if (!trancado && (await $.fs.exists(plain))) {
        if (await writePermanent($, { ...permanent, ...parse(await $.fs.read(plain)) })) await shred($, plain)
      }
    }
    if (trancado && problem === '') problem = 'Permanentes trancados: use "destravar" e digite sua senha.'
  }

  const keys = hasKeyctl ? parseProcKeys((await $.process.run(['cat', '/proc/keys'])).stdout) : []
  const next: Secrets = {}
  for (const k of keys) {
    let v = valueById.get(k.id)
    if (v === undefined) {
      const got = await keyctl($, ['pipe', String(k.id)])
      if (got.exitCode !== 0) continue
      v = got.stdout
      valueById.set(k.id, v)
    }
    next[k.name] = v
  }
  temporary = next

  const ttlOf = new Map(keys.map(k => [k.name, k.timeout]))
  const rows: SecretRow[] = Object.keys(all())
    .sort()
    .map(name => {
      const ttl = ttlOf.get(name)
      return ttl === undefined ? { name } : { name, ttl }
    })
  await update($, rowsAtom, () => rows)
  const names =
    (trancado ? '# permanentes trancados: peça à pessoa para destravar com /segredos\n' : '') +
    rows.map(r => `${r.name}\t${r.ttl === undefined ? 'permanente' : `temporário, expira em ${r.ttl}`}\n`).join('')
  if (names !== namesText) {
    await $.fs.write(`${dir}/segredos-nomes`, names)
    namesText = names
  }
  await update($, keyctlAtom, () => hasKeyctl)
  status($, rows.length)
}

// Cifra num temporário, confere que decifra igual e só então troca o arquivo.
async function writePermanent($: EngineInterface, next: Secrets): Promise<boolean> {
  if (grip === '' || trancado) {
    notice = grip === '' ? 'Defina uma senha antes de salvar um permanente.' : 'Destrave antes de mexer nos permanentes.'
    return false
  }
  const tmp = `${file}.tmp`
  const made = await gpg($, ['--yes', '--trust-model', 'always', '-r', UID, '-e', '-o', tmp], { stdin: serialize(next) })
  const back = await gpg($, ['-d', tmp])
  if (made.exitCode !== 0 || back.exitCode !== 0 || JSON.stringify(parse(back.stdout)) !== JSON.stringify(parse(serialize(next)))) {
    await $.process.run(['rm', '-f', tmp])
    notice = `Não consegui gravar ${file}: ${lastLine(made.stderr || back.stderr)}`
    return false
  }
  await $.process.run(['chmod', '600', tmp])
  await $.process.run(['mv', '-f', tmp, file])
  permanent = next
  mtime = await stamp($)
  return true
}

async function shred($: EngineInterface, path: string) {
  await $.process.run(['sh', '-c', 'shred -u "$1" 2>/dev/null || rm -f "$1"', 'sh', path])
}

async function hasLegacy($: EngineInterface) {
  return (await $.fs.exists(`${dir}/secrets.env.enc`)) || (await $.fs.exists(plain))
}

// Os permanentes da versão anterior; undefined se existem e não abrem.
async function legacySecrets($: EngineInterface): Promise<Secrets | undefined> {
  let out: Secrets = {}
  const enc = `${dir}/secrets.env.enc`
  if (await $.fs.exists(enc)) {
    let key: string | undefined
    const found = await keyctl($, ['search', '@u', 'user', LEGACY_KEY])
    if (found.exitCode === 0) key = (await keyctl($, ['pipe', found.stdout.trim()])).stdout.trim() || undefined
    if (key === undefined && (await $.fs.exists(`${dir}/secrets.key.dpapi`))) {
      const opened = await $.process.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', PS_UNPROTECT], {
        stdin: await $.fs.read(`${dir}/secrets.key.dpapi`),
      })
      if (opened.exitCode === 0) key = opened.stdout.trim() || undefined
    }
    if (key === undefined) return undefined
    const got = await $.process.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-pass', 'stdin', '-in', enc], {
      stdin: `${key}\n`,
    })
    if (got.exitCode !== 0) return undefined
    out = parse(got.stdout)
  }
  if (await $.fs.exists(plain)) out = { ...out, ...parse(await $.fs.read(plain)) }
  return out
}

async function dropLegacy($: EngineInterface) {
  for (const f of ['secrets.env.enc', 'secrets.key.dpapi', 'secrets.key.enc']) await shred($, `${dir}/${f}`)
  await shred($, plain)
  const found = await keyctl($, ['search', '@u', 'user', LEGACY_KEY])
  if (found.exitCode === 0) await keyctl($, ['invalidate', found.stdout.trim()])
}

// Cria a chave do cofre (o pinentry pede a senha nova duas vezes) e migra os permanentes antigos.
async function setup($: EngineInterface) {
  const legacy = await legacySecrets($)
  if (legacy === undefined) {
    notice = 'Não consegui abrir os permanentes da versão anterior; nada foi alterado.'
    return
  }
  await $.process.run(['mkdir', '-p', '-m', '700', home])
  await $.fs.write(`${home}/gpg-agent.conf`, `pinentry-program ${PINENTRY}\ndefault-cache-ttl ${IDLE}\nmax-cache-ttl ${MAX}\n`)
  await agent($, 'RELOADAGENT')
  const made = await gpg($, ['--quick-gen-key', UID, 'default', 'default', 'never'], { ask: true })
  grip = made.exitCode === 0 ? await findGrip($) : ''
  if (grip === '') {
    notice = failed(made)
    return
  }
  const info = await keyInfo($)
  if (!info.protectedByPassword) {
    notice = 'A chave ficou sem senha; apague ~/.claude/segredos-gnupg e tente de novo.'
    grip = ''
    return
  }
  trancado = !info.cached
  if (trancado) {
    const opened = await gpg($, ['--yes', '-r', UID, '--trust-model', 'always', '-e', '-o', file], { stdin: '' })
    const unlocked = opened.exitCode === 0 ? await gpg($, ['-d', file], { ask: true }) : opened
    if (unlocked.exitCode !== 0) {
      notice = `Senha definida, mas não destravou: ${failed(unlocked)}`
      return
    }
    trancado = false
  }
  if (await writePermanent($, legacy)) {
    await dropLegacy($)
    notice = 'Senha definida e permanentes migrados.'
  }
}

async function unlock($: EngineInterface) {
  if (asking) return
  asking = true
  try {
    if (grip === '') await setup($)
    else {
      const got = await gpg($, ['-d', file], { ask: true })
      notice = got.exitCode === 0 ? 'Destravado.' : failed(got)
      mtime = ''
    }
  } finally {
    asking = false
  }
  await load($)
  $.ui.invalidate('ui.render')
}

async function lock($: EngineInterface) {
  await agent($, 'RELOADAGENT')
  notice = 'Trancado.'
  await load($)
  $.ui.invalidate('ui.render')
}

async function changePassword($: EngineInterface) {
  if (asking) return
  asking = true
  try {
    const got = await gpg($, ['--passwd', UID], { ask: true })
    notice = got.exitCode === 0 ? 'Senha trocada.' : failed(got)
  } finally {
    asking = false
  }
  await load($)
  $.ui.invalidate('ui.render')
}

async function dropTemporary($: EngineInterface, name: string) {
  const got = await keyctl($, ['search', '@u', 'user', `${PREFIX}${name}`])
  if (got.exitCode === 0) await keyctl($, ['invalidate', got.stdout.trim()])
}

async function add($: EngineInterface, value: string) {
  const name = draftName.trim()
  const ttlText = draftTtl.trim() === '' ? DEFAULT_TTL : draftTtl.trim()
  const ttl = draftPermanent ? undefined : parseTtl(ttlText)
  let ok = false
  if (!NAME.test(name)) notice = `Nome inválido: "${name}"`
  else if (value === '') notice = 'Valor vazio.'
  else if (Number.isNaN(ttl)) notice = `Prazo inválido: "${draftTtl}" (ex.: 30m, 8h, 7d)`
  else if (!hasKeyctl) notice = 'Os segredos exigem keyctl: sudo apt install keyutils'
  else if (ttl === undefined) {
    if (grip === '' || trancado) await unlock($)
    if (await writePermanent($, { ...permanent, [name]: value })) {
      await dropTemporary($, name)
      notice = `${name} salvo (permanente).`
      ok = true
    }
  } else {
    if (name in permanent) {
      const { [name]: _old, ...rest } = permanent
      await writePermanent($, rest)
    }
    const made = await keyctl($, ['padd', 'user', `${PREFIX}${name}`, '@u'], value)
    const id = made.stdout.trim()
    if (made.exitCode !== 0 || id === '') notice = `Falhou: ${made.stderr.trim()}`
    else {
      await keyctl($, ['timeout', id, String(ttl)])
      valueById.delete(Number(id))
      notice = `${name} salvo, expira em ${ttlText}.`
      ok = true
    }
  }
  if (ok) {
    draftName = ''
    draftTtl = ''
    draftPermanent = false
  }
  await load($)
  $.ui.invalidate('ui.render')
}

async function remove($: EngineInterface, name: string) {
  if (name in temporary) await dropTemporary($, name)
  const { [name]: gone, ...rest } = permanent
  const ok = gone === undefined || (await writePermanent($, rest))
  if (ok) notice = `${name} removido.`
  await load($)
  $.ui.invalidate('ui.render')
}

function status($: EngineInterface, count: number) {
  $.ui.status(used ? `${trancado ? '🔒' : '🔑'} ${count}` : undefined)
}

// Chamado quando um comando cita segredos: liga a linha de status.
function markUsed($: EngineInterface) {
  if (used) return
  used = true
  status($, Object.keys(all()).length)
}

async function tick($: EngineInterface) {
  await load($)
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'segredos',
      description: 'Abre o painel de segredos (env vars injetadas no Bash)',
    })
    await load($)
    ticker?.cancel()
    ticker = $.clock.every(30_000, () => void tick($))
    return next(e)
  })

  on('command.run', { command: 'segredos' }, async $ => {
    await load($)
    await $.ui.open({ id: PANE, title: 'Segredos' })
    if (trancado) void unlock($)
    return {
      text: trancado
        ? 'Painel de segredos aberto; digite a senha na janela que abriu para destravar os permanentes.'
        : 'Painel de segredos aberto. Os valores nunca entram na conversa.',
    }
  })

  // Relê a cada comando (chave vencida, cofre trancado) e injeta só os segredos que o comando cita.
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    await load($)
    const secrets = all()
    if (Object.keys(secrets).length === 0) return next(e)
    const names = cited(e.command, Object.keys(secrets))
    if (names.length > 0) markUsed($)
    const ran = await next(names.length === 0 ? e : { ...e, command: wrap(e.command, loader, names) })
    if (ran.deny !== undefined) return ran
    const text = ran.text === undefined ? undefined : mask(ran.text, secrets)
    // Com erro o resultado é o texto do erro, não o registro do Bash: devolve com isError.
    return ran.isError
      ? { isError: true as const, result: maskDeep(ran.result, secrets), text }
      : { ...ran, result: maskDeep(ran.result, secrets), text, ref: undefined }
  }).catch(($, e, next) => next(e))

  on('tool.call', { tool: 'Monitor' }, async ($, e, next) => {
    if (e.command === undefined) return next(e)
    const names = cited(e.command, Object.keys(all()))
    if (names.length > 0) markUsed($)
    return next(names.length === 0 ? e : { ...e, command: wrap(e.command, loader, names) })
  }).catch(($, e, next) => next(e))

  on('prompt.compose', async ($, e, next) => {
    // Pode compor antes do session.start terminar: lê aqui também.
    await load($)
    const composed = await next(e)
    const rows = await read($, rowsAtom)
    if (rows.length === 0 && !trancado) return composed
    const list = rows.map(r => (r.ttl === undefined ? r.name : `${r.name} (temporário, expira em ${r.ttl})`))
    return {
      sections: [
        ...composed.sections,
        {
          id: 'segredos',
          scope: 'session' as const,
          text:
            '# Segredos disponíveis\n' +
            (trancado
              ? 'Os segredos permanentes estão trancados: se precisar de um, peça à pessoa para destravar com /segredos (nunca peça a senha).\n'
              : '') +
            (list.length > 0 ? `Disponíveis no Bash: ${list.join(', ')}.\n` : '') +
            'Cada comando recebe só os segredos cujo nome aparece nele: use $NOME, ou `export NOME; programa` para um programa que lê a variável sozinho. ' +
            'Nunca imprima, ecoe ou grave os valores; na saída eles aparecem mascarados como «NOME». ' +
            'Os temporários somem sozinhos ao vencer. Se faltar um segredo, peça à pessoa para cadastrá-lo com /segredos — nunca peça o valor no chat.',
        },
      ],
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const ui = $.ui.resolve(e)
    const rows = await read($, rowsAtom)
    if (!('Input' in ui)) {
      const { Box, Text } = ui
      return (
        <Box flexDirection="column">
          <Text>{rows.length === 0 ? 'Nenhum segredo cadastrado.' : rows.map(r => r.name).join(', ')}</Text>
          <Text dimColor>Para cadastrar, abra /segredos no desktop ou no terminal.</Text>
        </Box>
      )
    }
    const { Box, Text, Input, Button } = ui

    const state =
      grip === '' ? 'sem senha' : trancado ? '🔒 trancado' : `🔓 destravado (tranca após ${IDLE / 3600}h sem uso)`

    return (
      <Box flexDirection="column" gap={2} paddingY={1}>
        <Box flexDirection="column" gap={1}>
          <Text dimColor size="footnote">
            Permanentes: {state}
          </Text>
          <Box flexDirection="row" gap={1} flexWrap="wrap">
            {grip === '' && <Button key="setup" label="definir senha" variant="primary" onPress={() => void unlock($)} />}
            {grip !== '' && trancado && <Button key="unlock" label="destravar" variant="primary" onPress={() => void unlock($)} />}
            {grip !== '' && !trancado && <Button key="passwd" label="trocar senha" plain dimColor onPress={() => void changePassword($)} />}
            {grip !== '' && !trancado && <Button key="lock" label="trancar" onPress={() => void lock($)} />}
          </Box>
        </Box>
        {problem !== '' && <Text>{problem}</Text>}

        <Box flexDirection="column" gap={1}>
          <Text weight="semibold">Cadastrados</Text>
          <Box flexDirection="column" borderStyle="round" borderDimColor paddingX={1} paddingY={1} gap={1}>
            {rows.length === 0 && <Text dimColor>{trancado ? 'Destrave para ver os permanentes.' : 'Nenhum segredo ainda.'}</Text>}
            {rows.map(row => (
              <Box key={`row-${row.name}`} flexDirection="row" justifyContent="space-between" alignItems="center" gap={1}>
                <Box flexDirection="column" flexShrink={1}>
                  <Text mono wrap="truncate-end">
                    {row.name}
                  </Text>
                  <Text dimColor size="caption">
                    {row.ttl === undefined ? 'permanente' : `expira em ${row.ttl}`}
                  </Text>
                </Box>
                <Button key={`rm-${row.name}`} label="✕" plain dimColor onPress={() => void remove($, row.name)} />
              </Box>
            ))}
          </Box>
        </Box>

        <Box flexDirection="column" gap={1}>
          <Text weight="semibold">Novo segredo</Text>
          <Input
            key="name"
            label="Nome "
            placeholder="GITHUB_TOKEN"
            value={draftName}
            onInput={(v: string) => {
              draftName = v
            }}
            onSubmit={(v: string) => {
              draftName = v
            }}
          />
          <Box flexDirection="row" alignItems="center" gap={1} flexWrap="wrap">
            <Button
              key="permanent"
              label={`${draftPermanent ? '☑' : '☐'} permanente`}
              plain
              onPress={() => {
                draftPermanent = !draftPermanent
                $.ui.invalidate('ui.render')
              }}
            />
            {!draftPermanent && (
              <Input
                key="ttl"
                label="Prazo "
                placeholder={DEFAULT_TTL}
                value={draftTtl}
                onInput={(v: string) => {
                  draftTtl = v
                }}
                onSubmit={(v: string) => {
                  draftTtl = v
                }}
              />
            )}
          </Box>
          <Input
            key="value"
            label="Valor "
            placeholder="cole o valor e tecle Enter"
            submitLabel="salvar"
            onSubmit={(v: string) => void add($, v)}
          />
          {notice !== '' && <Text dimColor size="footnote">{notice}</Text>}
        </Box>

        <Text dimColor size="caption">
          Sem marcar, o segredo é temporário ({DEFAULT_TTL} se o prazo ficar vazio; ex.: 30m, 2h, 7d) e some ao vencer. Permanente fica
          cifrado com GnuPG e abre com a sua senha. Cada comando recebe só os segredos que cita, e os valores saem mascarados.
        </Text>
      </Box>
    )
  })
}
