# Exporta só os segredos pedidos: ". carregar.sh NOME..." (o mod passa os que o comando cita).
# Temporários vêm do keyring do kernel (prefixo "segredos:"); os demais, de secrets.env.gpg,
# decifrado em memória só se a senha já está no gpg-agent: daqui nunca abre janela de senha.
__temp=''
__perm=''
for __n in "$@"; do
  if keyctl search @u user "segredos:$__n" >/dev/null 2>&1; then __temp="$__temp $__n"; else __perm="$__perm $__n"; fi
done
__sf="$HOME/.claude/secrets.env.gpg"
if [ -n "$__perm" ] && [ -r "$__sf" ]; then
  __all=$(gpg --homedir "$HOME/.claude/segredos-gnupg" --batch --quiet --pinentry-mode error -d "$__sf" 2>/dev/null)
  eval "$__all"
  for __n in $(printf '%s\n' "$__all" | sed -nE 's/^export ([A-Za-z_][A-Za-z0-9_]*)=.*/\1/p'); do
    case " $__perm " in *" $__n "*) ;; *) unset "$__n" ;; esac
  done
fi
for __n in $(echo $__temp); do
  export "$__n=$(keyctl pipe "$(keyctl search @u user "segredos:$__n")" 2>/dev/null)"
done
unset __temp __perm __sf __all __n
