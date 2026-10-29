# segredos

Gerencia os segredos (tokens, chaves de API) que o Claude usa no Bash, sem que os valores entrem na conversa. Você cadastra pelo painel `/segredos`. Cada comando Bash do Claude recebe, como variáveis de ambiente, só os segredos cujo nome aparece nele, e qualquer valor que apareça na saída volta mascarado como `«NOME»`. O Claude recebe só os nomes.

## Requisitos

- Linux com interface gráfica para a janela de senha. No WSL, isso é o WSLg, que já vem no Windows 11 e no WSL atualizado.
- `gpg` (GnuPG 2.2 ou mais novo) e `pinentry-gtk2`
- `keyctl`

```bash
sudo apt install -y gnupg pinentry-gtk2 keyutils
```

## Instalação

No terminal (do WSL, Linux ou Mac), dentro de qualquer pasta:

```bash
claude plugin marketplace add ViniciusPolegario/Claude-Secrets-Mod
claude plugin install segredos@segredos
```

Abra uma sessão nova do Claude Code e rode `/segredos`. A instalação vale para o terminal e para o app desktop, inclusive na aba Code em sessões WSL, porque fica dentro da própria máquina (ou do WSL).

Para atualizar:

```bash
claude plugin marketplace update segredos
claude plugin update segredos@segredos
```

Ou ligue a atualização automática do marketplace em `/plugin`, aba **Marketplaces**.

## Uso

Abra `/segredos`, preencha **Nome** e **Valor** e tecle Enter. Por padrão o segredo é **temporário por 8h**; mude o **Prazo** se quiser outro tempo, ou marque **☐ permanente**. Para remover, use o **✕** ao lado do nome.

- **Permanente (caixa marcada):** cifrado com GnuPG em `~/.claude/secrets.env.gpg`, para uma chave só do mod, em `~/.claude/segredos-gnupg`, protegida pela sua senha.
  - No primeiro permanente, o botão **definir senha** abre a janela do GnuPG para você criar a senha.
  - Para usar os permanentes, você os **destrava** com a senha. O `gpg-agent` guarda a senha na memória por 2h sem uso, até 12h no total, ou até você clicar em **trancar**.
  - Enquanto trancados, nada no disco os revela, e os comandos simplesmente não os recebem: nenhuma janela abre sozinha.
  - **trocar senha** muda a senha sem recifrar nada.
- **Temporário (padrão 8h; ex.: `30m`, `2h`, `7d`):** fica só no keyring do kernel, que o apaga ao vencer. Não precisa de senha. Tudo some quando a máquina (ou o WSL) desliga.

Para importar segredos de uma vez, crie `~/.claude/secrets.env` com linhas `export NOME='valor'`. Com os permanentes destravados, o mod cifra o conteúdo e apaga o arquivo em texto puro.

Fora do Claude, carregue segredos num shell com `. <pasta do plugin>/scripts/carregar.sh NOME1 NOME2`. Os permanentes só vêm se estiverem destravados.

## Só o que o comando cita

Um comando recebe um segredo apenas se o nome dele aparece no texto do comando: `$TOKEN`, `${TOKEN}` ou `export TOKEN; npm run deploy`, para um programa que lê a variável sozinho. Assim, um `npm install` qualquer não leva junto as suas chaves.

## Cuidados

- **Esqueceu a senha, perdeu os permanentes.** Não há recuperação. Cadastre-os de novo depois de apagar `~/.claude/segredos-gnupg` e `~/.claude/secrets.env.gpg`.
- Faça backup de `~/.claude/segredos-gnupg` junto com `secrets.env.gpg`: um não abre sem o outro.
- Destravados, os segredos ficam acessíveis a qualquer processo do seu usuário que peça ao `gpg-agent`. Use **trancar** quando não precisar deles.
