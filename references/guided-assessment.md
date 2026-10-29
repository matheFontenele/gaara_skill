<!-- gaara-module
id: guided-assessment
version: 1.0
requires: [security-communication, finding-schema, appsec-assessment]
scripts: [assessment_report.py]
-->

# Avaliação Guiada a partir de Relatórios Existentes

## Objetivo e limites

Use esta rotina quando a pessoa já tiver relatórios da Gaara e precisar entender o conjunto: **o que foi encontrado, o que pode significar, o que falta confirmar e por onde começar**.

`assessment_report.py` é um montador de relatórios, não um scanner. Ele lê apenas os JSONs indicados, não abre o projeto nem o host, não faz consultas externas e não altera sistemas. O resumo nunca substitui os relatórios originais.

## Delimitação

Se o contexto não estiver claro, pergunte no máximo três itens, por exemplo:

1. Os arquivos representam o mesmo projeto/host e a mesma avaliação?
2. Quais relatórios correspondem a código, produção ou logs — e qual o ambiente relevante?
3. A prioridade é decidir o que investigar, planejar correções ou preparar uma comunicação?

Não peça esses dados se eles já estiverem nos relatórios ou na conversa. Não conclua que relatórios com datas, escopos ou ambientes diferentes são diretamente comparáveis.

## Executar o montador

Passe os JSONs já gerados. Rótulos ajudam a identificar cada entrada:

```bash
python3 scripts/assessment_report.py \
  --input deps=/tmp/deps.json \
  --input php=/tmp/php.json \
  --input postura=/tmp/postura.json \
  --input logs=/tmp/logs.json \
  --format md --output /tmp/avaliacao.md
```

Para integração, use `--format json`. `--input` pode ser repetido e aceita `rótulo=arquivo.json` ou apenas `arquivo.json`. O programa falha com código 2 se um arquivo não puder ser lido ou tiver estrutura básica inválida. Não inclua em comandos caminhos que exponham nomes sensíveis em um terminal compartilhado.

## Como interpretar a saída

- O resumo agrupa achados e destaca até três prioridades; os demais continuam no anexo JSON e nos relatórios originais.
- Achados de dependência com o mesmo advisory, pacote e versão são reconhecidos entre rótulos. CVEs únicos, registros e ocorrências são contagens diferentes.
- Achados sem identidade pública estável são mantidos por categoria, título e referência local dentro de cada rótulo; não são presumidos como o mesmo evento entre fontes.
- A prioridade reflete a severidade registrada nos relatórios. KEV significa que há exploração conhecida em algum contexto, não que este sistema foi atacado.
- Referências de evidência podem indicar arquivo e localização, mas o montador não copia trechos. Consulte os JSONs originais para as evidências redigidas e fontes completas.
- Cobertura e lacunas são apresentadas quando estão estruturadas no relatório. “Não observado” não significa “não avaliado”.

## Regras de conclusão

1. Diga “os relatórios fornecidos registram...” e identifique datas/escopos relevantes.
2. Separe fato observado, impacto possível e confirmação pendente.
3. Não declare comprometimento, exposição, exploração, correção em produção ou segurança global com base apenas neste resumo.
4. Recomende uma verificação concreta antes de atualização, alteração de configuração ou rotação de segredo.
5. Se houver discrepância entre resumo e JSON, prevalece a revisão dos relatórios originais; corrija o montador antes de apoiar decisão nele.

## Formato da resposta ao usuário

Comece pelo resumo curto em linguagem clara. Em seguida explique até três prioridades, o que ainda não foi avaliado e um próximo passo seguro. Ofereça o anexo técnico sem despejar todos os registros na primeira resposta. Siga também `security-communication.md`.
