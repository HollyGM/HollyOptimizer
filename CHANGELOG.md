# Histórico de mudanças

Todas as alterações relevantes do HollyOptimizer serão registradas neste arquivo.
O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não publicado]

### Planejado

- Empacotamento público assinado e notarizado para distribuição fora da máquina de desenvolvimento.

## [0.7.0] - 2026-08-18

### Adicionado

- Painel **Permissões**: verifica automaticamente, ao abrir o app, Acesso Total ao Disco e as duas autorizações de Automação (Finder e System Events) usadas pelo aplicativo, e leva o usuário direto ao painel correto dos Ajustes do Sistema para cada uma. Um aviso no Dashboard aparece sempre que algo precisa de atenção.
- Resumo por **Apple Intelligence** on-device (Foundation Models) no Dashboard: reescreve o resumo determinístico de uma varredura em uma frase mais natural, sem alterar nenhum número. Roda inteiramente no dispositivo, opcional, e falha em silêncio (volta ao resumo padrão) em qualquer Mac ou versão do macOS sem suporte.
- Duas novas categorias de limpeza reversível: cache do **Cargo** (Rust) e cache do **Gradle** (Android/Java), seguindo a mesma política de segurança das demais.
- Ordenação por "Dias Inativo" na aba Arquivos Grandes, para achar arquivos esquecidos e não só os maiores.

### Corrigido

- Itens rejeitados pela própria política de segurança (link simbólico, pacote de documento, item fora do escopo) eram registrados como "falha inesperada" no relatório de varredura; agora aparecem com uma mensagem correta de bloqueio por política.

## [0.6.2] - 2026-08-08

### Adicionado

- Nova identidade HollyOptimizer, com ícone e marca próprios.
- Auditoria somente leitura de aplicativos Apple Silicon, Intel, universais, web apps e scripts.
- Diagnóstico de chip, núcleos, memória unificada, Rosetta 2 e swap.
- Cobertura ampliada de caches, inicialização, navegadores, duplicados e itens de inventário manual.
- Testes de segurança e autoteste do bundle.

### Corrigido

- Validação das categorias selecionadas na limpeza do sistema.
- Tratamento seguro de snapshots locais do Time Machine como inventário, nunca limpeza automática.
- Proteções contra remoção de cookies, bancos de dados e caminhos sensíveis.
- Mensagens de permissão, acesso limitado e operações recusadas pelo macOS.

### Alterado

- Renomeação completa do antigo projeto MacBoster para HollyOptimizer.
- Build nativo para Apple Silicon com suporte opcional a `universal2`.
- Dependências atualizadas e fixadas para builds reproduzíveis.

[Não publicado]: https://github.com/HollyGM/HollyOptimizer/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/HollyGM/HollyOptimizer/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/HollyGM/HollyOptimizer/releases/tag/v0.6.2
