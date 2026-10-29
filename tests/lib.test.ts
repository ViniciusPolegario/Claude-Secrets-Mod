import { expect, test } from 'claude-code/testing'

import { cited, mask, maskDeep, parse, parseProcKeys, parseTtl, serialize, wrap } from '../hooks/lib.ts'

test('serialize/parse ida e volta com aspas e caracteres de shell', () => {
  const s = { B: "it's $HOME `x` \"q\"", A: 'simples' }
  expect(parse(serialize(s))).toEqual(s)
})

test('parse aceita arquivo editado à mão', () => {
  expect(parse('# c\nFOO=bar\nexport BAZ="a\\"b"\n  \nlixo')).toEqual({ FOO: 'bar', BAZ: 'a"b' })
})

test('mascara valores na saída, inclusive aninhados, e ignora valores curtos', () => {
  const s = { TOKEN: 'ghp_abcdef', PIN: '12' }
  expect(mask('x ghp_abcdef y 12', s)).toBe('x «TOKEN» y 12')
  expect(maskDeep({ stdout: ['ghp_abcdef'], n: 1 }, s)).toEqual({ stdout: ['«TOKEN»'], n: 1 })
})

test('wrap carrega só os segredos citados antes do comando', () => {
  expect(wrap('echo $X', "/m/it's/carregar.sh", ['X', 'Y'])).toBe(". '/m/it'\\''s/carregar.sh' X Y\necho $X")
})

test('cited acha o nome como palavra, não como pedaço', () => {
  const names = ['TOKEN', 'GH', 'API_KEY']
  expect(cited('curl -H "x: ${TOKEN}" $API_KEY', names)).toEqual(['TOKEN', 'API_KEY'])
  expect(cited('export GH; npm run deploy', names)).toEqual(['GH'])
  expect(cited('echo $GHOST $MY_TOKEN', names)).toEqual([])
})

test('parseTtl', () => {
  expect(parseTtl('')).toBe(undefined)
  expect(parseTtl('8h')).toBe(28800)
  expect(parseTtl('1h30m')).toBe(5400)
  expect(Number.isNaN(parseTtl('8 horas'))).toBe(true)
  expect(Number.isNaN(parseTtl('0m'))).toBe(true)
})

test('parseProcKeys pega só chaves do mod que não venceram', () => {
  const proc = [
    '1a2b3c4d I--Q---     1  59m 3f010000  1000  1000 user      segredos:GH_TOKEN: 12',
    '0000000a I--Q---     1 perm 3f010000  1000  1000 user      segredos:OUTRO: 3',
    '0000000b I--Q---     1 expd 3f010000  1000  1000 user      segredos:VELHO: 3',
    '0000000c I--Q---     1 perm 3f010000  1000  1000 user      alheia: 3',
    '0000000d I--Q---     1 perm 1f030000  1000  1000 keyring   _uid.1000: 1',
  ].join('\n')
  expect(parseProcKeys(proc)).toEqual([
    { id: 0x1a2b3c4d, name: 'GH_TOKEN', timeout: '59m' },
    { id: 10, name: 'OUTRO', timeout: 'perm' },
  ])
})
