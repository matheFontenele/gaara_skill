<!-- gaara-module
id: severity-matrix
version: 1.0
requires: [finding-schema]
scripts: []
-->

# Matriz de Severidade, Confiança e Autonomia

> Use este arquivo antes de propor qualquer ação. Severidade define **urgência**; confiança define **se pode agir**.

---

## 1. Níveis de severidade

| Nível | Critério objetivo | Exemplos | Ação autônoma | SLA |
|---|---|---|---|---|
| **Crítico** | Comprometimento confirmado, ou iminente, com impacto direto em dados, disponibilidade ou controle do host | RCE com execução comprovada; webshell ativa; login de root/sudo de IP novo; exfiltração em curso; credencial de banco exposta e válida | **Nenhuma ação destrutiva.** Ban/contenção somente com aprovação. Escalar para humano imediatamente | 15 min |
| **Alto** | Exploração provável ou em andamento, sem confirmação de sucesso | Brute force volumoso; LFI retornando conteúdo; upload de arquivo executável; CVE crítico com sistema exposto e sem patch; scanner agressivo com path sensível em 200 | Ban ≤ 24h **com aprovação** + relatório | 4 h |
| **Médio** | Atividade anômala sustentada, sem indício de sucesso | Scan de enumeração; flood de 404; brute force moderado; scraping agressivo; pico de erro 5xx | Ban ≤ 1h **com aprovação** | 24 h |
| **Baixo** | Ruído de internet ou comportamento esperado | Crawlers legítimos; 404 aleatório; tentativas isoladas | Apenas registrar | Semanal |

### 1.1 Regra de escalada

Escale o nível quando houver **qualquer** um destes:

- Sucesso de autenticação após falhas do mesmo IP.
- Resposta 200 para payload de exploração.
- Processo filho do servidor web executando shell ou download.
- Conexão de saída da conta do serviço web.
- Arquivo novo ou modificado no webroot fora de janela de deploy.
- Crash repetido de worker (`SIGSEGV`) sem explicação.

### 1.2 Regra de rebaixamento

Só rebaixe com **explicação benigna documentada**, nunca por conveniência:

- IP pertence a monitoramento próprio, com registro.
- User-Agent identificado e comportamento consistente com o declarado.
- Janela de deploy ou teste conhecida.
- Tráfego interno de health check.

Registre o motivo do rebaixamento. "Achei que não era nada" não é justificativa.

### 1.3 Severidade condicional

Severidade é sempre **um valor único**. Quando o risco depende de uma condição — "se esse serviço não é usado" — classifique pelo **pior caso** e escreva a condição na recomendação.

Não escreva "ALTO se…" no campo de severidade. Isso quebra o schema e impede comparação entre achados.

---

## 2. Confiança

| Nível | Definição | Exemplo |
|---|---|---|
| **Alta** | Evidência direta, correlacionada em duas ou mais fontes | `Failed password` no auth.log + 401 no Nginx, mesmo IP, mesma janela |
| **Média** | Padrão claro, mas com lacuna | Só o access log disponível; sem error log para confirmar |
| **Baixa** | Indício isolado, com explicação benigna plausível | Um único 404 em `/.env` |

### 2.1 Matriz de decisão

| | Confiança alta | Confiança média | Confiança baixa |
|---|---|---|---|
| **Crítico** | Conter + escalar agora | Conter + investigar em paralelo | Investigar antes de qualquer ação |
| **Alto** | Ban com aprovação | Ban com aprovação, TTL curto | Investigar; não banir |
| **Médio** | Ban com aprovação | Registrar + monitorar | Registrar |
| **Baixo** | Registrar | Registrar | Ignorar |

**Regra de ouro:** severidade alta + confiança baixa = **investigar**, não agir. Banir por palpite cria indisponibilidade e treina o time a ignorar alerta.

---

## 3. Exemplos resolvidos

### Exemplo A — brute force SSH

```
Evidência: 312 linhas "Failed password for invalid user" de 203.0.113.45,
           entre 02:10 e 02:41 de 24/10 (auth.log)
           Nenhum "Accepted" para o mesmo IP.
```
Severidade: **Alto**. Confiança: **Alta**. Ação: ban 24h com aprovação.
Racional: volume alto e sustentado, mas sem sucesso → não é crítico.

### Exemplo B — LFI com resposta 200

```
Evidência: GET /index.php?page=../../../../etc/passwd → 200, 1.2 KB
           GET /index.php?page=php://filter/convert.base64-encode/resource=config → 200
```
Severidade: **Crítico**. Confiança: **Alta**. Ação: conter + escalar; assumir leitura de arquivos.
Racional: 200 em payload de traversal é indício forte de exploração bem-sucedida.

### Exemplo C — worker morrendo

```
Evidência: 47 ocorrências de "child ... exited on signal 11 (SIGSEGV)"
           em php-fpm, iniciando 21/10 14:07, antes estável.
```
Severidade: **Alto** (sobe para Crítico se houver sinal de execução). Confiança: **Média**.
Ação: investigar; cruzar com CVE de runtime; verificar processos e conexões.
Racional: crash pode ser tentativa de exploração de corrupção de memória — ou bug de extensão. A correlação temporal decide.

### Exemplo D — bot de monitoramento

```
Evidência: 1 req/min de 198.51.100.20 em /health, UA "UptimeRobot/2.0",
           todos 200, há 90 dias.
```
Severidade: **Baixo**. Confiança: **Alta** (comportamento histórico).
Ação: registrar; adicionar à allowlist se confirmado com o time.
Racional: consistência histórica é a melhor evidência de benignidade.

---

## 4. O que nunca fazer em cada nível

| Nível | Proibido |
|---|---|
| Crítico | Remediar sozinho; apagar arquivo; reiniciar serviço sem preservar evidência; "limpar" para ver se resolve |
| Alto | Banir sem TTL; banir em massa; alterar configuração de serviço |
| Médio | Banir sem evidência citável; ignorar e fechar sem registro |
| Baixo | Criar alerta que vai gerar fadiga; notificar o usuário com urgência falsa |

---

## 5. Prazos e escalada

| Nível | Primeira resposta | Atualização | Encerramento |
|---|---|---|---|
| Crítico | 15 min | a cada 30 min | após erradicação + verificação |
| Alto | 4 h | diária | após mitigação |
| Médio | 24 h | — | após ação ou decisão de não agir |
| Baixo | semanal | — | no digest |

**Escalar para humano sempre que:** houver dúvida sobre escopo, a ação exigir mais que ban, ou o impacto envolver dado pessoal (LGPD).
