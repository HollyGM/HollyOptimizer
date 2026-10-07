# Histórico de mudanças

Todas as alterações relevantes do HollyOptimizer serão registradas neste arquivo.
O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não publicado]

### Planejado

- Empacotamento público assinado e notarizado para distribuição fora da máquina de desenvolvimento.

## [0.7.3] - 2026-10-02

### Segurança

- Remoções de duplicados são serializadas para impedir que duas solicitações simultâneas removam cópias opostas e deixem o conjunto sem um arquivo preservado.

### Corrigido

- Varreduras repetidas de arquivos grandes e duplicados mantêm o progresso e o botão de cancelamento até a conclusão da solicitação atual, mesmo quando o backend ainda informa a conclusão anterior.
- A ordenação de duplicados preserva cada conjunto com seu cabeçalho SHA-256 e sua cópia protegida, usando o tamanho exato em bytes.
- Os cartões do Dashboard exibem o estado ainda não analisado antes da primeira varredura, em vez de indicar um carregamento contínuo.
- Caches de navegador que recebem alterações comuns após a análise podem ser enviados à Lixeira depois da revalidação completa, preservando o bloqueio de itens substituídos ou protegidos.
- A interface de terminal trata itens de início de sessão pela API própria, com confirmação, e rejeita números zero ou negativos na seleção de navegadores.
- O aplicativo compilado declara o macOS mínimo exigido pelos binários nativos embarcados, incluindo o Python.
- O build resolve a raiz do projeto antes de manipular artefatos e recusa arquitetura incompatível também em compilações locais.

### Testes

- Novas regressões comportamentais para progresso da interface, limpeza de caches, remoção concorrente de duplicados, menus de terminal e requisitos do bundle.

## [0.7.2] - 2026-09-30

### Segurança

- **A limpeza de caches agora valida todo o conteúdo de cada item antes de enviá-lo à Lixeira.** Antes, só o item de topo passava pela política de segurança e o restante era apenas somado ao tamanho; um diretório de cache com aparência segura podia conter um pacote de documento, um item gerenciado por serviço de nuvem, um link simbólico ou um item de outro proprietário e ser movido inteiro. Agora toda a subárvore é validada durante a varredura e revalidada imediatamente antes da movimentação: se algo protegido aparecer depois da varredura, a operação falha de forma segura e o item permanece no lugar.
- **Interface reforçada contra HTML injetado por nomes de arquivos e de aplicativos.** `escapeHtml` passou a escapar também aspas simples e duplas (a função é usada dentro de atributos entre aspas), os botões da aba de inicialização deixaram de usar `onclick` inline e uma Content Security Policy passou a bloquear scripts e manipuladores de evento inline, além de conexões de rede a partir do WebView.
- **O desinstalador não confia mais no nome do aplicativo enviado pela interface.** A busca de arquivos de suporte usa somente o bundle identifier e o nome registrados pela última listagem confiável de aplicativos.
- **O resumo por Apple Intelligence é descartado se alterar qualquer número.** Se o texto reescrito pelo modelo mudar, omitir ou inventar um valor (tamanhos, porcentagens ou contagens), ou vier vazio, o app volta ao resumo determinístico padrão.

### Alterado

- A política de remoção passou a aceitar itens dentro de `~/Library/Application Scripts`, pasta que o desinstalador já varria em busca de sobras (scripts de aplicativos com sandbox). A pasta raiz continua protegida.
- Dependências atualizadas: PyObjC 12.2.1 → 12.2.2 (os seis pacotes, que precisam subir juntos) e PyInstaller 6.22.0 → 6.22.3.
- Sete novos testes de segurança cobrem os itens acima.

## [0.7.1] - 2026-08-18

### Corrigido

- **Esvaziar Lixeira podia falhar com "Operação cancelada na autenticação do macOS"** logo após abrir o app, ou às vezes de forma intermitente. Causa: a nova checagem automática de Permissões (0.7.0) enviava um AppleEvent real ao Finder a cada abertura do app, o mesmo canal usado por Esvaziar Lixeira; se o usuário clicasse em Esvaziar enquanto essa checagem ainda estava em andamento, os dois pedidos concorrentes podiam colidir e o macOS reportava a ação real como cancelada.
  - A checagem automática ao abrir o app agora verifica **somente** Acesso Total ao Disco (um probe passivo, sem AppleEvent). Automação (Finder/System Events) só é testada quando o usuário abre a aba Permissões ou clica em "Verificar Novamente" — um gesto deliberado.
  - Toda chamada de Automação ao Finder ou ao System Events (Esvaziar Lixeira, itens de início de sessão, e a própria checagem de Permissões) agora é serializada por um lock dedicado por aplicativo-alvo, para que duas nunca corram ao mesmo tempo mesmo em cliques rápidos.

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

[Não publicado]: https://github.com/HollyGM/HollyOptimizer/compare/v0.7.3...HEAD
[0.7.3]: https://github.com/HollyGM/HollyOptimizer/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/HollyGM/HollyOptimizer/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/HollyGM/HollyOptimizer/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/HollyGM/HollyOptimizer/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/HollyGM/HollyOptimizer/releases/tag/v0.6.2
