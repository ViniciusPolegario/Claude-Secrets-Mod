---
name: usar-segredos
# Só para o Claude: /segredos é o comando do painel, e a skill não pode tomar o lugar dele no menu.
user-invocable: false
description: Use quando a pessoa digitar /segredos (o painel do plugin segredos) ou mencionar o plugin segredos, sobretudo se o comando /segredos não existir nesta sessão, e sempre que uma tarefa precisar de um token, chave de API, senha ou outro segredo. Explica como usar os segredos no Bash sem ver os valores e como instalar o plugin quando o comando não existe.
---

# Segredos

A pessoa guarda segredos pelo painel `/segredos`. Você nunca vê os valores, só os nomes.

## Quais existem

```bash
cat ~/.claude/segredos-nomes
```

Uma linha por segredo: `NOME<TAB>permanente` ou `NOME<TAB>temporário, expira em 7h`. Se a primeira linha diz que os permanentes estão trancados, os nomes deles não aparecem até a pessoa destravar.

## Como usar

- Cada comando Bash recebe só os segredos cujo nome aparece no texto do comando. Use `$NOME` ou `${NOME}`. Para um programa que lê a variável sozinho, cite o nome: `export NOME; npm run deploy`.
- Para conferir se um segredo chegou, sem ver o valor: `[ -n "$NOME" ] && echo ok`.
- Na saída, qualquer valor de segredo aparece mascarado como `«NOME»`.

## Se o `/segredos` não existe nesta sessão

O painel e a injeção dos segredos vêm do módulo de hooks do plugin; sem ele instalado nesta máquina, só esta skill pode ter chegado. Sinais: `/segredos` vira texto comum e `~/.claude/segredos-nomes` não existe ou está velho. Passe à pessoa a instalação, no terminal (no WSL, se for o caso):

```bash
claude plugin marketplace add ViniciusPolegario/Claude-Secrets-Mod
claude plugin install segredos@segredos
```

Depois, abrir uma sessão nova.

## Regras

- Nunca imprima, ecoe, grave em arquivo, commit ou mensagem o valor de um segredo. Nunca rode `gpg -d` no cofre (`~/.claude/secrets.env.gpg`) nem leia o keyring.
- Faltou um segredo: peça para a pessoa cadastrar com `/segredos`. O padrão é temporário de 8h; para guardar de vez, ela marca "permanente". Nunca peça o valor no chat.
- Permanentes trancados: peça para a pessoa abrir `/segredos` e destravar. Nunca peça a senha.
