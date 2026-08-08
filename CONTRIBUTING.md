# Como contribuir

Obrigado pelo interesse em melhorar o HollyOptimizer. Como o aplicativo pode mover arquivos e alterar itens de inicialização, toda contribuição deve preservar o modelo de segurança do projeto.

## Preparação

1. Use macOS 12 ou posterior e Python 3.12 ou posterior.
2. Crie um fork e uma branch curta para a mudança.
3. Prepare o ambiente:

```bash
python3.12 -m venv .venv
.venv/bin/python3 -m pip install --upgrade pip
.venv/bin/python3 -m pip install -r requirements.txt
```

## Antes de enviar

Execute:

```bash
.venv/bin/python3 -m unittest discover -s tests -v
.venv/bin/python3 hollyoptimizer_gui.py --self-test
.venv/bin/python3 -m compileall -q core hollyoptimizer.py hollyoptimizer_gui.py
node --check gui/app.js
```

Além dos testes automatizados, confirme que:

- nenhuma credencial, caminho pessoal ou arquivo gerado entrou no commit;
- qualquer remoção exige intenção explícita do usuário;
- arquivos elegíveis continuam recuperáveis pela Lixeira;
- caminhos são novamente validados imediatamente antes de uma alteração;
- cookies, bancos de dados, Keychains, iCloud, Mail, Messages e SSH permanecem bloqueados;
- novas mensagens da interface explicam claramente o que será feito.

## Pull requests

- Descreva o problema e a solução.
- Mantenha cada pull request focado em uma mudança coerente.
- Inclua testes para correções e novos comportamentos.
- Anexe capturas quando houver alteração visual.
- Não misture formatação ampla com uma correção funcional sem necessidade.

Falhas de segurança não devem ser publicadas em uma issue comum. Siga [SECURITY.md](SECURITY.md).
