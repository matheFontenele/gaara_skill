<!-- gaara-module
id: behavioral-detection
version: 1.0
requires: [detection-playbook, severity-matrix, finding-schema]
scripts: [log_triage]
-->

# Detecção Comportamental

> Assinatura responde "esse payload apareceu?". Comportamento responde "esse ator está agindo fora do padrão?". A segunda pergunta é a que pega ataque novo — e a que mais gera falso positivo quando feita sem baseline.

---

## 1. Por que assinatura não basta

| Problema | Consequência |
|---|---|
| Payload muda a cada campanha | Regex de ontem não pega o ataque de hoje |
| Ofuscação trivial (URL-encode, base64, unicode) | Assinatura em texto cru perde o sinal |
| Ataque lento e distribuído | Nenhuma requisição isolada é anômala |
| Log injection | Atacante escreve o que quer que a regex encontre — ou não encontre |

Comportamento não muda tão rápido quanto payload. Quem faz força bruta precisa de volume; quem enumera precisa de cardinalidade; quem exfiltra precisa de saída.

**Mas comportamento sem baseline é chute com aparência de rigor.** Os limiares deste arquivo são ponto de partida, não verdade.

---

## 2. Baseline antes de limiar

### 2.1 Como construir

| Item | Regra |
|---|---|
| Janela | 7 dias no mínimo; 30 é melhor. Menos que isso não cobre semana útil |
| Corte | Percentil 95 e 99, **nunca média**. A média esconde a cauda, e a cauda é onde mora o ataque |
| Segmentação | Por ator (IP, conta, chave de API) **e** por rota/serviço |
| Sazonalidade | Compare com o mesmo horário e o mesmo dia da semana |
| Exceções | Registre deploy, campanha, backup e teste de carga. Sem isso, o baseline mente |
| Revisão | Recalibre após mudança de arquitetura, não só de tempo |

### 2.2 Baseline envenenado

Um atacante paciente age pouco por dia, durante semanas, até o "normal" incluir o ataque. Depois escala.

Contramedida: **primeira ocorrência de um ator nunca é normal por definição**. Um IP, conta ou chave vista pela primeira vez entra em observação, mesmo com volume baixo. É a categoria `meta/baseline-poisoning`.

---

## 3. Detectores

### 3.1 Velocidade (rate)

Contagem por unidade de tempo. Pega força bruta, flooding, scraping agressivo.

- Pergunta: "quantas vezes em quanto tempo?"
- Cuidado: rajada legítima de retry, health check, sincronização.

### 3.2 Cardinalidade (distinct count)

Quantos valores distintos o ator tocou. Pega spraying, enumeração de IDs, varredura de usuários.

- Pergunta: "quantos usuários/IDs/rotas diferentes?"
- Sinal forte: muitas tentativas, poucas por alvo.
- Cuidado: crawler legítimo também tem cardinalidade alta — mas concentrado em rotas de conteúdo.

### 3.3 Razão (ratio)

Proporção entre dois contadores. Pega scan (404/total), credential stuffing (401/POST), abuso de API (429/total).

- Pergunta: "qual a proporção de falha sobre o total?"
- Vantagem: independe do volume absoluto.
- Cuidado: base pequena distorce (3 requisições, 3 erros = 100%).

### 3.4 Sequência

Evento A seguido de B dentro de uma janela. É o detector mais valioso e o mais mal usado.

| Sequência | Leitura |
|---|---|
| Falhas → `Accepted` | Credencial comprometida — **crítico**, não é só ban |
| `POST /upload` 2xx → `GET` do arquivo | Webshell provável |
| Scan de paths → acesso a path sensível 200 | Reconhecimento que deu certo |
| `SIGSEGV` → processo filho `sh` | Exploração de runtime com execução |
| Falha de login → criação de usuário → sudo | Escalada pós-comprometimento |

**Sequência não é causalidade.** Dois eventos na mesma janela podem ser independentes. A conclusão precisa do vínculo (mesmo IP, mesma conta, mesma sessão).

### 3.5 Primeira ocorrência (first-seen)

Valor nunca visto antes: IP, ASN, User-Agent, domínio de saída, chave de API.

- Pergunta: "isso já apareceu alguma vez?"
- Poderoso contra ataque novo.
- Ruído alto: internet é grande. Use como **elevador de confiança**, não como achado sozinho.

### 3.6 Periodicidade (beaconing)

Intervalos regulares com baixa variação. Pega C2 que se disfarça de tráfego normal.

- Método: coeficiente de variação dos intervalos (`desvio / média`). CV < 0,15 em ≥ 10 amostras é suspeito.
- Cuidado: agente de monitoração, NTP, health check e telemetria também são periódicos. Verifique destino e dono.

### 3.7 Desvio de par (peer group)

Comparar o ator com os semelhantes, não com a média global. Um servidor de banco falando 2 MB/s é normal; um servidor web falando 2 MB/s não é.

- Agrupe por função: web, banco, cache, worker.
- Compare com o p99 do grupo.

### 3.8 Ausência

O que deveria existir e não existe também é sinal.

- Log de auditoria que parou de chegar.
- Backup que não rodou.
- Registrar `SIGSEGV` mas nenhum log de aplicação na mesma janela.
- Ausência de sinal **não prova ausência de comprometimento** — pode provar que o atacante desligou o log.

---

## 4. Janelas

Janela fixa (minuto cheio) esconde ataque a cavalo. Use janela deslizante.

| Janela | Uso típico |
|---|---|
| 1 min | Flood, scan rápido, pico de erro |
| 5 min | Força bruta moderada, retry agressivo |
| 10 min | Spraying (cardinalidade de usuários) |
| 1 h | Força bruta sustentada, abuso de API |
| 24 h | Credential stuffing distribuído, exfiltração lenta |
| 7 d | Baseline, primeira ocorrência, desvio de par |

O `log_triage.py` usa janela deslizante de 1, 5, 10 e 60 minutos para os limiares do `detection-playbook.md`.

---

## 5. Correlação

### 5.1 Chave de correlação

Escolha uma chave estável e significativa: IP, conta, chave de API, fingerprint de TLS, ASN. Correlacionar por "hora" não é correlação.

### 5.2 Regra prática

| Famílias distintas para o mesmo ator | Leitura |
|---|---|
| 1 | Hipótese |
| 2 | Provável ator único — eleve a confiança |
| 3+ | Ator determinado — eleve a severidade do conjunto |

No `log_triage.py`, atores com dois ou mais achados entram em `summary.correlations`.

### 5.3 Exemplo

`203.0.113.45` aparece em scan de paths, força bruta SSH e LFI com resposta 200. Isoladamente: médio, alto e crítico. Juntos: um ator que reconheceu, tentou credencial e explorou arquivo — o conjunto é **incidente**, não três eventos separados.

### 5.4 O que não concluir

- Mesmo IP ≠ mesma pessoa (NAT, proxy, VPS compartilhada).
- Mesma janela ≠ mesma campanha.
- Correlação não substitui evidência de execução.

---

## 6. O que o log não vê

| Ponto cego | Onde ver |
|---|---|
| Acesso remoto por RustDesk/AnyDesk | Autenticação no protocolo, fora do PAM. Verificar serviço e configuração |
| Processo filho do servidor web | `ps --forest`, EDR, auditd |
| Conexão de saída | `ss -tunp`, firewall, proxy |
| Corpo da requisição | Access log não guarda body; precisa de app log ou captura |
| C2 sobre TLS legítimo | Só metadados: SNI, destino, volume, periodicidade |
| Alteração de arquivo | Integridade (AIDE, git no webroot, inotify) |

**Ausência de sinal em log de acesso não é absolvição.** Declare o ponto cego no relatório.

---

## 7. Implementação no `log_triage.py`

| Detector | Entrada | Saída |
|---|---|---|
| Velocidade | `auth.log`, `access.log` | `max_5min`, `max_1h`, `max_requests_1min` |
| Cardinalidade | usuários distintos por IP | `distinct_users`, `spray_users_10min` |
| Razão | 404 / total | `not_found`, `max_requests_1min` |
| Sequência | falha→sucesso, POST→GET | achado crítico / alto |
| Payload | path, UA, referer | traversal, SQLi, RCE, injection |
| Runtime | PHP-FPM | `SIGSEGV`, OOM |
| Correlação | ator | `summary.correlations` |

```bash
./scripts/log_triage.py /var/log/auth.log /var/log/nginx/access.log --since 24h
./scripts/log_triage.py app.log --format md
./scripts/log_triage.py app.log --now 2026-10-24T23:00:00Z --scan-id gaara-20261024-0001
```

Limitações da v1:

- Limiar estático do playbook; ainda não aprende baseline sozinho.
- Não lê corpo de requisição nem telemetria de host.
- Beaconing e desvio de par estão documentados, mas não implementados no script.

---

## 8. Calibração

1. Rode 7 dias em modo somente leitura e conte falsos positivos por regra.
2. Ajuste o limiar, não a severidade. Severidade é consequência.
3. Registre o ajuste e a data no relatório de mudança.
4. Não persiga zero alerta: limiar alto demais troca ruído por ponto cego.
5. Revise após incidente — o ataque que passou mostra onde o limiar estava errado.

---

## 9. Anti-padrões

| Anti-padrão | Por quê é ruim |
|---|---|
| "Volume alto = ataque" | Backup e deploy também têm volume alto |
| "Nunca visto = malicioso" | Internet produz primeiro contato o tempo todo |
| "Mesmo IP = mesmo ator" | NAT e VPS compartilhada |
| "Correlação prova causalidade" | Prova coincidência temporal, não vínculo |
| "Baseline de 1 dia" | Não cobre sazonalidade |
| "Ajustei até parar de alertar" | Você pode ter silenciado o ataque |
| "O log não mostrou nada, então está limpo" | Log pode estar incompleto ou desligado |
