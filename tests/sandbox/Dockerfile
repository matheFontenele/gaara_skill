# Sandbox do Lote 5: roda a suíte inteira sem Fail2ban real e sem rede.
#
# Construir na raiz do repositório:
#   docker build -f tests/sandbox/Dockerfile -t gaara-lote5 .
#
# Executar:
#   docker run --rm --network none gaara-lote5
#
# Os testes usam um cliente Fail2ban falso em diretório temporário. Nenhum
# jail, firewall ou configuração do host é tocado.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /work

COPY assets ./assets
COPY references ./references
COPY scripts ./scripts
COPY tests ./tests
COPY SKILL.md ./

RUN chmod +x scripts/*.py scripts/*.sh

CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]
