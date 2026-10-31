# Gaara — segurança defensiva em linguagem simples

O Gaara é um **assistente de segurança defensiva** para servidores Linux e aplicações web. Ele ajuda a entender o que está acontecendo, separar o que é urgente do que pode esperar e decidir qual é o próximo passo seguro.

Ele foi pensado para quem cuida de um site, de um servidor ou de um projeto, mas **não trabalha com segurança o dia inteiro**. A ideia é simples: menos alarmismo e mais explicação clara, com evidência e limites.

> **Estado:** público, em evolução, sob licença MIT. A instalação é manual nesta versão. Guia completo de instalação e referência técnica: [`docs/guia-tecnico.md`](docs/guia-tecnico.md).

---

## 1. Para quem é

- Dono de projeto ou gestor que precisa entender um alerta de segurança.
- Pessoa de infraestrutura ou desenvolvimento que quer uma segunda opinião.
- Time pequeno que ainda não tem um especialista dedicado.
- Quem está começando e quer aprender o motivo de cada recomendação.

O Gaara **não substitui** um profissional de segurança, um antivírus, um firewall ou um processo de resposta a incidentes. Ele organiza o problema e ajuda a decidir; a responsabilidade pela mudança continua sendo de uma pessoa.

---

## 2. O que ele ajuda a responder

| Sua dúvida | O que o Gaara faz |
|---|---|
| “Tem ataque nesse log?” | Lê os logs, separa tentativas de acesso, varredura e comportamento suspeito, e mostra o que merece atenção. |
| “Meu servidor está configurado de forma segura?” | Verifica pontos como SSH, firewall, permissões e atualizações, e explica o risco de cada um. |
| “Fui invadido?” | Orienta a coleta de sinais, preserva evidências e indica contenção — sem apagar rastros. |
| “Meu projeto tem alguma vulnerabilidade?” | Inventaria bibliotecas e versões, consulta avisos públicos quando autorizado e mostra o que ficou fora da análise. |
| “Meu PHP antigo ainda é seguro?” | Explica o risco de sistemas sem atualização e o que fazer quando não existe correção. |
| “Como explico isso para a diretoria?” | Gera um resumo curto, sem siglas desnecessárias, com prioridade e próximo passo. |

Também ajuda com bloqueio de IP no Fail2ban, geração de relatórios e comparação entre duas avaliações. Tudo isso é opcional e só acontece com o seu comando.

---

## 3. O que ele não faz

- Não faz pentest, exploit, teste de invasão ou varredura em sistemas de terceiros.
- Não garante que um sistema está “100% seguro”.
- Não substitui backup, monitoramento contínuo ou revisão humana.
- Não cobre Windows, Active Directory ou resposta a incidentes nesses ambientes.
- Não altera firewall, SSH, arquivos ou serviços por conta própria.

---

## 4. Como começar

Você precisa de **Git**, **Python 3.10 ou mais recente** e um assistente que leia o arquivo `SKILL.md` — por exemplo, OpenCode ou Hermes Agent.

### 4.1 Baixar

```bash
git clone https://github.com/matheFontenele/gaara_skill.git
cd gaara_skill
export GAARA_REPO="$PWD"
```

### 4.2 Instalar no OpenCode

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills"
ln -s "$GAARA_REPO" "${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills/gaara"
```

Abra uma **sessão nova** do OpenCode e peça em linguagem natural.

### 4.3 Instalar no Hermes Agent

```bash
mkdir -p ~/.hermes/skills/security
ln -s "$GAARA_REPO" ~/.hermes/skills/security/gaara
hermes skills list | grep -i gaara
```

Depois:

```bash
hermes chat -q "/gaara analisa /var/log/auth.log e me diz se há ataque"
```

### 4.4 Outros assistentes

Codex, Claude Code, Gemini/Antigravity, Cursor/Cline e agentes genéricos também podem usar o mesmo núcleo. Os comandos, caminhos, permissões e a instalação em cópia estão no [guia técnico](docs/guia-tecnico.md).

> Se o seu assistente não tiver acesso a terminal, ele pode ler os arquivos e entregar os comandos para você executar. Ele nunca deve inventar uma saída de ferramenta.

---

## 5. Como pedir

Fale como você falaria com uma pessoa. Não precisa decorar nome de ferramenta.

- “Analisa este log e me diz se alguém está tentando entrar no servidor.”
- “Meu servidor está seguro? O que eu deveria corrigir primeiro?”
- “Acho que fui invadido. O que eu faço agora sem apagar as evidências?”
- “Meu projeto usa uma biblioteca com falha conhecida. Isso é grave?”
- “Tenho PHP 5.6 em produção. Não consigo atualizar. O que posso fazer?”
- “Explica esse relatório para alguém que não é técnico.”

Se o pedido for muito amplo, o Gaara faz até três perguntas curtas para entender o ambiente antes de responder.

---

## 6. Como ler a resposta

Toda resposta começa pelo que mais importa:

1. **Resumo para você:** o que foi encontrado e se precisa de ação agora.
2. **O que isso significa:** a consequência possível, sem afirmar que já aconteceu.
3. **O que foi confirmado e o que falta confirmar:** fato, hipótese e lacuna ficam separados.
4. **Próximo passo seguro:** uma ação concreta, com objetivo e risco.

### 6.1 Quatro perguntas para qualquer vulnerabilidade

Quando o assunto for uma falha de segurança, o Gaara usa sempre o mesmo padrão:

#### 1. O que é

Explica a falha em palavras simples, sem começar por siglas. Se houver um identificador público, como um CVE, ele aparece depois da explicação, com a fonte e a data da consulta.

#### 2. Como ocorre

Conta como o problema pode ser explorado na prática: qual parte do sistema é afetada, o que a pessoa atacante precisa conseguir e quais ferramentas ou condições aparecem no caminho. A explicação é didática, não um passo a passo de ataque.

#### 3. Quais os impactos

Mostra o que pode ser afetado no servidor ou no projeto: dados, contas, disponibilidade, reputação ou custo. Também deixa claro o que ainda **não** foi confirmado — por exemplo, se a versão vulnerável está realmente em produção.

#### 4. Como prevenir ou remediar

Separa os dois cenários:

- **Prevenir:** como evitar que o problema aconteça, com atualização, configuração, ferramenta ou mudança de processo.
- **Remediar:** o que fazer se o problema já ocorreu, com contenção, coleta de evidências, correção e verificação.

Sempre que possível, indica o esforço, o risco da mudança e como voltar atrás.

### 6.2 Exemplo curto

> **1. O que é:** uma biblioteca usada pelo projeto tem uma falha conhecida na versão instalada.
>
> **2. Como ocorre:** em certas condições, uma entrada enviada para a aplicação pode ser interpretada de forma errada e executar uma ação que não deveria. Isso depende de a parte afetada estar em uso e exposta.
>
> **3. Quais os impactos:** se a condição existir, alguém poderia acessar ou alterar informações. Ainda não sabemos se essa parte do sistema está em produção, nem se houve tentativa de exploração.
>
> **4. Como prevenir ou remediar:** confirmar a versão em produção, testar a atualização compatível e manter um backup para rollback. Se houver sinal de acesso indevido, conter o serviço, preservar os logs e trocar as credenciais afetadas.

### 6.3 Palavras que aparecem

| Palavra | O que significa na prática |
|---|---|
| Confirmado | Foi visto nos arquivos ou logs analisados. |
| Possível impacto | Pode acontecer se as condições se confirmarem; não é prova de ataque. |
| Não avaliado | A ferramenta não olhou aquilo; não quer dizer que está seguro. |
| CVE | Identificador público de uma falha de segurança. |
| Severidade | Gravidade técnica estimada; não mede sozinha o risco no seu ambiente. |
| Prioridade | O que vale investigar ou corrigir primeiro. |

---

## 7. Segurança e controle

O Gaara foi feito para **observar primeiro**. Os scripts de análise são somente leitura.

- Nada é alterado sem uma autorização explícita, na mesma conversa.
- Antes de uma mudança, ele mostra o comando, o alvo, o efeito, o risco e como reverter.
- O bloqueio de IP pelo Fail2ban é opcional, usa lista de proteção, tempo limitado e registro de auditoria.
- Senhas, tokens, cookies e chaves são ocultados nos relatórios.
- A redação é uma proteção adicional, não uma garantia absoluta: revise antes de compartilhar.

Se uma ferramenta não estiver disponível, o Gaara diz **“não executado”** e explica o que falta. Ele não simula resultados.

---

## 8. Testar sem colocar produção em risco

- Use uma máquina virtual, container ou ambiente de teste.
- Prefira os logs e fixtures de exemplo do repositório.
- Não execute `f2b_guard.py` com `--execute` em produção durante os primeiros testes.
- Remova dados de clientes, credenciais e chaves antes de compartilhar um log.
- Leia o resultado e confirme se faz sentido para o seu ambiente.

Para rodar a suíte de testes:

```bash
cd "$GAARA_REPO"
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## 9. Instalação detalhada

O [guia técnico](docs/guia-tecnico.md) contém:

- instalação por OpenCode, Hermes, Codex, Claude Code, Gemini/Antigravity e Cursor/Cline;
- permissões do OpenCode e proteção contra escrita no Hermes;
- uso manual dos scripts;
- configuração do Fail2ban;
- portabilidade, testes e solução de problemas.

---

## 10. Perguntas frequentes

**Preciso saber Linux?**

Ajuda, mas não é obrigatório para começar. O Gaara explica os termos e mostra o comando exato para você revisar.

**Preciso pagar?**

Não. O projeto está sob licença MIT.

**Funciona sem internet?**

A maior parte da análise funciona offline. A consulta de vulnerabilidades conhecidas pode usar a internet; sem rede, ela informa o que não foi avaliado.

**Posso usar em produção?**

As análises de leitura, sim. Qualquer alteração deve ser testada antes, feita com aprovação explícita e com rollback disponível.

**O score de segurança é uma certificação?**

Não. É uma estimativa baseada apenas nos controles que a ferramenta conseguiu avaliar. Cobertura baixa aparece como insuficiente, não como nota alta.

**O que é um CVE?**

É um identificador público de uma falha de segurança. Ele ajuda a encontrar informações, mas não prova sozinho que o seu sistema foi afetado ou invadido.

---

## 11. Feedback e contribuições

Encontrou um problema ou tem uma sugestão? Abra uma issue no repositório ou fale com o mantenedor pelo canal combinado.

Ao reportar, inclua:

- o commit testado (`git rev-parse --short HEAD`);
- o assistente usado;
- o comando e o resultado esperado;
- um trecho sanitizado da saída.

Nunca cole senhas, tokens, chaves, `.env` ou dados de clientes em uma issue pública.

Contribuições são bem-vindas dentro do escopo defensivo do projeto. Antes de abrir um pull request grande, converse com o mantenedor. A suíte de testes precisa continuar verde.

---

## 12. Licença

MIT. Consulte o arquivo [`LICENSE`](LICENSE).
