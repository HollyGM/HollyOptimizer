#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.apps import delete_leftover, scan_leftovers
from core.browser_cleaner import clean_browser_cache, scan_browser_caches
from core.dependencies import check_homebrew, check_npm, check_pip, clean_homebrew
from core.duplicates import delete_duplicate_files, scan_duplicates
from core.junk import clean_target, scan_junk
from core.large_files import delete_large_file, scan_large_files
from core.memory import get_memory_stats, get_top_ram_processes, kill_process
from core.network import flush_dns, run_network_diagnostic
from core.security_audit import run_security_audit
from core.startup import scan_startup, toggle_startup_item
from core.uninstaller import get_app_related_files, list_installed_apps, uninstall_app
from core.utils import Colors, format_size
from core.version import APP_NAME


def clear_screen() -> None:
    """Clears an ANSI-compatible terminal without spawning a shell."""
    print("\033[2J\033[H", end="")

def print_header(title: str):
    print(f"\n{Colors.BOLD}{Colors.HEADER}=== {title} ==={Colors.ENDC}")

def show_main_menu():
    print(
        f"\n{Colors.BOLD}{Colors.BLUE}⚡ {APP_NAME} CLI — Manutenção segura do macOS "
        f"⚡{Colors.ENDC}"
    )
    print(f"{Colors.GRAY}Seu sistema limpo, leve e otimizado.{Colors.ENDC}\n")
    print(f"{Colors.CYAN}[1]{Colors.ENDC} 🧹 Varredura de Lixo do Sistema (Caches, Logs, Xcode)")
    print(f"{Colors.CYAN}[2]{Colors.ENDC} 🗑️  Localizador de Sobras de Apps Desinstalados")
    print(f"{Colors.CYAN}[3]{Colors.ENDC} 📦 Analisador de Dependências (Homebrew, NPM, Pip)")
    print(f"{Colors.CYAN}[4]{Colors.ENDC} 🚀 Otimizador de Inicialização (LaunchAgents)")
    print(f"{Colors.CYAN}[5]{Colors.ENDC} 📂 Localizador de Arquivos Grandes")
    print(f"{Colors.CYAN}[6]{Colors.ENDC} 📋 Detector de Arquivos Duplicados")
    print(f"{Colors.CYAN}[7]{Colors.ENDC} 🌐 Rede e DNS")
    print(f"{Colors.CYAN}[8]{Colors.ENDC} 💾 Monitor de Memória RAM")
    print(f"{Colors.CYAN}[9]{Colors.ENDC} 🗑️  Desinstalador de Aplicativos")
    print(f"{Colors.CYAN}[10]{Colors.ENDC} 🧭 Limpeza de Navegadores (Safari, Firefox e Chromium)")
    print(f"{Colors.CYAN}[11]{Colors.ENDC} 🛡️  Central de Segurança do macOS")
    print(f"{Colors.CYAN}[0]{Colors.ENDC} ❌ Sair")


def menu_browser_caches():
    print_header("LIMPEZA DE NAVEGADORES")
    print(
        f"{Colors.GRAY}Somente caches temporários. Histórico, cookies, senhas, "
        f"sessões, favoritos e extensões são preservados.{Colors.ENDC}"
    )
    results = scan_browser_caches()
    available = []

    print(f"\n{Colors.BOLD}{'Nº':<4} | {'Navegador':<12} | {'Estado':<12} | {'Itens':<10} | {'Tamanho':<10}{Colors.ENDC}")
    print("-" * 64)
    for index, (key, data) in enumerate(results.items(), 1):
        if not data["accessible"]:
            state, color = "Sem acesso", Colors.WARNING
        else:
            state = "Aberto" if data["running"] else "Fechado"
            color = Colors.WARNING if data["running"] else Colors.GREEN
        print(
            f"{index:<4} | {data['name']:<12} | {color}{state:<12}{Colors.ENDC} | "
            f"{data['count']:<10} | {data['size_human']:<10}"
        )
        available.append((key, data))

    choice = input("\nEscolha um navegador para mover o cache para a Lixeira (Enter para voltar): ").strip()
    if not choice:
        return
    try:
        key, data = available[int(choice) - 1]
    except (ValueError, IndexError):
        print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")
        return

    if data["running"]:
        print(f"{Colors.WARNING}Feche completamente o {data['name']} e faça uma nova varredura.{Colors.ENDC}")
        return
    if not data["accessible"]:
        print(
            f"{Colors.WARNING}O macOS bloqueou o acesso ao cache do {data['name']}. "
            f"Conceda Acesso Total ao Disco ao {APP_NAME} e faça uma nova varredura.{Colors.ENDC}"
        )
        return
    if data["size_bytes"] <= 0:
        print(f"{Colors.GREEN}Nenhum cache temporário foi encontrado.{Colors.ENDC}")
        return

    confirm = input(
        f"Mover {data['size_human']} de cache do {data['name']} para a Lixeira? (s/N): "
    ).strip().lower()
    if confirm != "s":
        print(f"{Colors.GRAY}Operação cancelada.{Colors.ENDC}")
        return

    result = clean_browser_cache(key)
    for error in result["errors"]:
        print(f"  {Colors.WARNING}[Aviso]{Colors.ENDC} {error}")
    print(
        f"\n{Colors.GREEN}✓ {format_size(result['bytes_moved'])} movidos para a Lixeira "
        f"({result['files_moved']} arquivos).{Colors.ENDC}"
    )


def menu_security_audit():
    print_header("CENTRAL DE SEGURANÇA DO macOS")
    print(f"{Colors.GRAY}Diagnóstico somente leitura; nenhuma configuração será alterada.{Colors.ENDC}\n")
    report = run_security_audit()
    colors = {"ok": Colors.GREEN, "attention": Colors.WARNING, "unknown": Colors.GRAY}

    for check in report["checks"]:
        color = colors[check["status"]]
        print(f"  {color}{check['label']:<16}{Colors.ENDC} {Colors.BOLD}{check['name']}{Colors.ENDC}")
        print(f"    {Colors.GRAY}{check['detail']}{Colors.ENDC}")
        if check["recommendation"]:
            print(f"    {check['recommendation']}")
            print(f"    {Colors.CYAN}{check['settings_hint']}{Colors.ENDC}")

    summary = report["summary"]
    print(
        f"\nResumo: {Colors.GREEN}{summary['ok']} protegidos{Colors.ENDC}, "
        f"{Colors.WARNING}{summary['attention']} requerem atenção{Colors.ENDC}, "
        f"{Colors.GRAY}{summary['unknown']} não verificados{Colors.ENDC}."
    )

def menu_junk_cleaner():
    print_header("VARREDURA DE LIXO DO SISTEMA")
    print(f"{Colors.GRAY}Escaneando caches, arquivos de log, lixeira e Xcode...{Colors.ENDC}")

    results = scan_junk()
    total_size = 0
    total_files = 0

    print(f"\n{Colors.BOLD}{'Categoria':<25} | {'Quantidade':<10} | {'Tamanho':<10} | Descrição{Colors.ENDC}")
    print("-" * 80)

    for key, data in results.items():
        size_bytes = data["size_bytes"]
        count = data["count"]
        if data.get("cleanable"):
            total_size += size_bytes
            total_files += count

        color = Colors.WARNING if size_bytes > 0 else Colors.GREEN
        size_str = f"{color}{data['size_human']}{Colors.ENDC}"
        name = data["name"] if data.get("cleanable") else f"{data['name']} (revisão manual)"

        print(f"{name:<25} | {count:<10} | {size_str:<19} | {data['description']}")

    print("-" * 80)
    print(f"{Colors.BOLD}Total Potencial de Limpeza: {Colors.WARNING}{format_size(total_size)}{Colors.ENDC} em {total_files} arquivos.")
    print(f"{Colors.GRAY}Categorias marcadas como 'revisão manual' são apenas inventário e não serão limpas.{Colors.ENDC}")

    if total_size > 0:
        confirm = input("\nDeseja limpar os arquivos listados? (s/N): ").strip().lower()
        if confirm == 's':
            print(f"\n{Colors.BLUE}Limpando arquivos de lixo...{Colors.ENDC}")
            freed_total = 0
            files_deleted_total = 0
            for key in results.keys():
                if not results[key].get("cleanable"):
                    continue
                result = clean_target(key)
                freed_total += result["bytes_moved"]
                files_deleted_total += result["files_moved"]
                for error in result["errors"]:
                    print(f"  {Colors.WARNING}[Aviso]{Colors.ENDC} {error}")
            print(f"{Colors.GREEN}✓ Limpeza concluída! Liberação total de {Colors.BOLD}{format_size(freed_total)}{Colors.ENDC} ({files_deleted_total} arquivos removidos).{Colors.ENDC}")
        else:
            print(f"{Colors.GRAY}Operação cancelada. Nenhum arquivo foi removido.{Colors.ENDC}")
    else:
        print(f"\n{Colors.GREEN}✓ Seu sistema já está limpo! Nenhum arquivo de lixo detectado.{Colors.ENDC}")

def menu_app_leftovers():
    print_header("SOBRAS DE APLICATIVOS DESINSTALADOS")
    print(f"{Colors.GRAY}Mapeando aplicativos ativos e rastreando arquivos órfãos em pastas de suporte...{Colors.ENDC}")

    leftovers = scan_leftovers()

    if not leftovers:
        print(f"\n{Colors.GREEN}✓ Nenhuma sobra de aplicativo desinstalado foi detectada no seu sistema.{Colors.ENDC}")
        return

    total_size = sum(item["size_bytes"] for item in leftovers)
    print(f"\nEncontradas {Colors.WARNING}{len(leftovers)}{Colors.ENDC} pastas/arquivos de sobras consumindo {Colors.WARNING}{format_size(total_size)}{Colors.ENDC}:\n")

    leftovers.sort(key=lambda x: x["size_bytes"], reverse=True)

    print(f"{Colors.BOLD}{'Nº':<4} | {'Nome/Pasta':<30} | {'Tamanho':<10} | {'Tipo':<12} | Caminho{Colors.ENDC}")
    print("-" * 100)

    for idx, item in enumerate(leftovers, 1):
        name = item["name"]
        if len(name) > 30:
            name = name[:27] + "..."

        type_desc = {
            "support": "Suporte App",
            "cache": "Cache",
            "saved_state": "Estado Salvo",
            "preferences": "Preferência",
            "container": "Container"
        }.get(item["type"], item["type"])

        print(f"{idx:<4} | {name:<30} | {item['size_human']:<10} | {type_desc:<12} | {Colors.GRAY}{item['path']}{Colors.ENDC}")

    print("-" * 100)
    print(f"Total: {Colors.WARNING}{format_size(total_size)}{Colors.ENDC} ocupados por sobras.")

    print(f"\n{Colors.BOLD}Opções de Remoção:{Colors.ENDC}")
    print("  - Digite 'todos' para remover TODAS as sobras encontradas.")
    print("  - Digite o número ou números separados por vírgula (ex: 1,3,4) para remover sobras específicas.")
    print("  - Pressione Enter para voltar ao menu principal.")

    user_input = input("\nEscolha uma opção: ").strip().lower()
    if not user_input:
        return

    targets_to_delete = []
    if user_input == "todos":
        targets_to_delete = leftovers
    else:
        try:
            indices = [int(i.strip()) - 1 for i in user_input.split(",") if i.strip()]
            for idx in indices:
                if 0 <= idx < len(leftovers):
                    targets_to_delete.append(leftovers[idx])
                else:
                    print(f"{Colors.FAIL}Número inválido: {idx + 1}{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")
            return

    if not targets_to_delete:
        print(f"{Colors.GRAY}Nenhuma ação realizada.{Colors.ENDC}")
        return

    print(f"\n{Colors.WARNING}⚠️  ATENÇÃO: Você escolheu remover {len(targets_to_delete)} itens.{Colors.ENDC}")
    confirm = input("Tem certeza de que deseja mover esses arquivos para a Lixeira? (s/N): ").strip().lower()
    if confirm == 's':
        freed = 0
        success_count = 0
        for item in targets_to_delete:
            success, msg = delete_leftover(item["path"])
            if success:
                freed += item["size_bytes"]
                success_count += 1
                print(f"  {Colors.GREEN}[Removido]{Colors.ENDC} {item['name']}")
            else:
                print(f"  {Colors.FAIL}[Erro - {msg}]{Colors.ENDC} {item['name']}")
        print(f"\n{Colors.GREEN}✓ Limpeza concluída! {success_count} itens movidos para a Lixeira ({Colors.BOLD}{format_size(freed)}{Colors.ENDC}).{Colors.ENDC}")
    else:
        print(f"{Colors.GRAY}Remoção cancelada.{Colors.ENDC}")

def menu_dependencies():
    print_header("ANALISADOR DE DEPENDÊNCIAS")
    print(f"{Colors.GRAY}Verificando gerenciadores de pacotes de desenvolvimento...{Colors.ENDC}")

    brew = check_homebrew()
    npm = check_npm()
    pip = check_pip()

    print("\n--- STATUS DOS GERENCIADORES ---")

    if brew["installed"]:
        print(f"📦 {Colors.BOLD}Homebrew:{Colors.ENDC} {Colors.GREEN}Instalado{Colors.ENDC} ({brew['path']})")
        print(f"   └─ Pacotes do usuário (Leaves): {Colors.CYAN}{len(brew['leaves'])}{Colors.ENDC} pacotes")

        orph_color = Colors.WARNING if brew["orphans"] else Colors.GREEN
        print(f"   └─ Pacotes órfãos (Inúteis): {orph_color}{len(brew['orphans'])}{Colors.ENDC} pacotes")
        if brew["orphans"]:
            print(f"      └─ Órfãos detectados: {Colors.GRAY}{', '.join(brew['orphans'][:10])}{'...' if len(brew['orphans']) > 10 else ''}{Colors.ENDC}")

        clean_color = Colors.WARNING if brew["cleanup_size"] != "0 B" else Colors.GREEN
        print(f"   └─ Cache limpável: {clean_color}{brew['cleanup_size']}{Colors.ENDC} ({brew['cleanup_files_count']} arquivos)")
    else:
        print(f"📦 {Colors.BOLD}Homebrew:{Colors.ENDC} {Colors.GRAY}Não instalado ou não localizado{Colors.ENDC}")

    if npm["installed"]:
        print(f"\n🟢 {Colors.BOLD}NPM (Node Package Manager):{Colors.ENDC} {Colors.GREEN}Instalado{Colors.ENDC}")
        print(f"   └─ Módulos Globais: {Colors.CYAN}{len(npm['global_packages'])}{Colors.ENDC} instalados")
        if npm["global_packages"]:
            print(f"      └─ Pacotes: {Colors.GRAY}{', '.join(npm['global_packages'][:6])}{'...' if len(npm['global_packages']) > 6 else ''}{Colors.ENDC}")
    else:
        print(f"\n🟢 {Colors.BOLD}NPM (Node Package Manager):{Colors.ENDC} {Colors.GRAY}Não instalado ou não localizado{Colors.ENDC}")

    if pip["installed"]:
        print(f"\n🐍 {Colors.BOLD}Pip (Python Package Manager):{Colors.ENDC} {Colors.GREEN}Instalado{Colors.ENDC}")
        print(f"   └─ Pacotes Globais/Usuário: {Colors.CYAN}{len(pip['global_packages'])}{Colors.ENDC} instalados")
        if pip["global_packages"]:
            print(f"      └─ Pacotes: {Colors.GRAY}{', '.join(pip['global_packages'][:6])}{'...' if len(pip['global_packages']) > 6 else ''}{Colors.ENDC}")
    else:
        print(f"\n🐍 {Colors.BOLD}Pip (Python Package Manager):{Colors.ENDC} {Colors.GRAY}Não instalado ou não localizado{Colors.ENDC}")

    if brew["installed"] and (brew["orphans"] or brew["cleanup_size"] != "0 B"):
        print(f"\n{Colors.BOLD}Ações disponíveis para Homebrew:{Colors.ENDC}")
        print(f"  {Colors.CYAN}[1]{Colors.ENDC} Remover dependências órfãs (`brew autoremove`)")
        print(f"  {Colors.CYAN}[2]{Colors.ENDC} Limpar cache de downloads do Homebrew (`brew cleanup`)")
        print(f"  {Colors.CYAN}[3]{Colors.ENDC} Executar ambas as limpezas")
        print(f"  {Colors.CYAN}[4]{Colors.ENDC} Voltar ao menu principal")

        choice = input("\nEscolha uma ação: ").strip()
        if choice in ('1', '2', '3'):
            clean_orphans = choice in ('1', '3')
            clean_cache = choice in ('2', '3')

            print(f"\n{Colors.BLUE}Executando operações do Homebrew...{Colors.ENDC}")
            logs = clean_homebrew(clean_orphans=clean_orphans, clean_cache=clean_cache)
            for log in logs:
                print(log)
            print(f"{Colors.GREEN}✓ Ações concluídas!{Colors.ENDC}")
        else:
            return
    else:
        input(f"\n{Colors.BOLD}Pressione Enter para voltar ao menu principal...{Colors.ENDC}")

def menu_startup():
    while True:
        print_header("OTIMIZADOR DE INICIALIZAÇÃO")
        print(f"{Colors.GRAY}Procurando serviços carregados na inicialização do macOS...{Colors.ENDC}")

        items = scan_startup()
        if not items:
            print(f"\n{Colors.GREEN}✓ Nenhum item de inicialização encontrado.{Colors.ENDC}")
            input("\nPressione Enter para voltar...")
            break

        print(f"\n{Colors.BOLD}{'Nº':<4} | {'Estado':<12} | {'Tipo':<25} | Serviço (Label) / Comando{Colors.ENDC}")
        print("-" * 100)

        for idx, item in enumerate(items, 1):
            if item["is_disabled"]:
                status = f"{Colors.GRAY}[DESATIVADO]{Colors.ENDC}"
            elif item["is_broken"]:
                status = f"{Colors.FAIL}[QUEBRADO]{Colors.ENDC}"
            else:
                status = f"{Colors.GREEN}[ATIVO]{Colors.ENDC}"

            cat_name = item["category_name"]
            if len(cat_name) > 25:
                cat_name = cat_name[:22] + "..."

            label = item["label"]
            if item["is_broken"]:
                label += f" {Colors.FAIL}(⚠️ Executável não encontrado!){Colors.ENDC}"

            print(f"{idx:<4} | {status:<21} | {cat_name:<25} | {Colors.BOLD}{label}{Colors.ENDC}")
            print(f"{'':<4} | {'':<12} | {'':<25} | {Colors.GRAY}Caminho: {item['exec_path']}{Colors.ENDC}")
            print("-" * 100)

        print(f"\n{Colors.BOLD}Instruções:{Colors.ENDC}")
        print("  - Digite o número do item para ALTERNAR o estado (Ativar <-> Desativar).")
        print("  - Pressione Enter para voltar ao menu principal.")

        user_input = input("\nEscolha uma opção: ").strip()
        if not user_input:
            break

        try:
            idx = int(user_input) - 1
            if 0 <= idx < len(items):
                target = items[idx]
                action_desc = "ativar" if target["is_disabled"] else "desativar"

                if target["sudo_required"] and os.geteuid() != 0:
                    print(f"\n{Colors.WARNING}⚠️  AVISO: Este item pertence ao sistema. Para {action_desc} este item, o script precisa ser executado com 'sudo'.{Colors.ENDC}")
                    confirm = input("Deseja tentar mesmo assim? (s/N): ").strip().lower()
                    if confirm != 's':
                        continue

                success, msg = toggle_startup_item(target["filepath"], disable=not target["is_disabled"])
                if success:
                    print(f"\n{Colors.GREEN}✓ {msg}{Colors.ENDC}")
                else:
                    print(f"\n{Colors.FAIL}✗ {msg}{Colors.ENDC}")

                input("\nPressione Enter para atualizar a lista...")
            else:
                print(f"{Colors.FAIL}Número fora da lista.{Colors.ENDC}")
                input("\nPressione Enter para continuar...")
        except ValueError:
            print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")
            input("\nPressione Enter para continuar...")

def menu_large_files():
    print_header("LOCALIZADOR DE ARQUIVOS GRANDES")
    print(f"{Colors.GRAY}Busca em Downloads, Documentos, Desktop, Movies, Music e Pictures...{Colors.ENDC}")

    print(f"\n{Colors.BOLD}Tamanho mínimo:{Colors.ENDC}")
    print(f"  {Colors.CYAN}[1]{Colors.ENDC} 50 MB")
    print(f"  {Colors.CYAN}[2]{Colors.ENDC} 100 MB (padrão)")
    print(f"  {Colors.CYAN}[3]{Colors.ENDC} 500 MB")
    print(f"  {Colors.CYAN}[4]{Colors.ENDC} 1 GB")

    size_choice = input("\nEscolha (1-4, Enter=100 MB): ").strip()
    min_size = {"1": 50.0, "2": 100.0, "3": 500.0, "4": 1000.0}.get(size_choice, 100.0)

    print(f"\n{Colors.BLUE}Buscando arquivos maiores que {min_size:.0f} MB...{Colors.ENDC}")
    files = scan_large_files(min_size_mb=min_size)

    if not files:
        print(f"\n{Colors.GREEN}✓ Nenhum arquivo maior que {min_size:.0f} MB encontrado.{Colors.ENDC}")
        return

    print(f"\nEncontrados {Colors.WARNING}{len(files)}{Colors.ENDC} arquivos grandes:\n")
    print(f"{Colors.BOLD}{'Nº':<4} | {'Nome':<30} | {'Tamanho':<10} | {'Modificado':<16} | {'Dias Inativo':<12} | Caminho{Colors.ENDC}")
    print("-" * 120)

    for idx, item in enumerate(files, 1):
        name = item["name"]
        if len(name) > 30:
            name = name[:27] + "..."
        print(f"{idx:<4} | {name:<30} | {Colors.WARNING}{item['size_human']:<10}{Colors.ENDC} | {item['modified']:<16} | {item['days_inactive']:<12} | {Colors.GRAY}{item['path']}{Colors.ENDC}")

    total_size = sum(f["size_bytes"] for f in files)
    print("-" * 120)
    print(f"Total: {Colors.WARNING}{format_size(total_size)}{Colors.ENDC} em {len(files)} arquivos.")

    print(f"\n{Colors.BOLD}Opções:{Colors.ENDC}")
    print("  - Digite números separados por vírgula (ex: 1,3,5) para mover à Lixeira.")
    print("  - Pressione Enter para voltar.")

    user_input = input("\nEscolha: ").strip()
    if not user_input:
        return

    try:
        indices = [int(i.strip()) - 1 for i in user_input.split(",") if i.strip()]
    except ValueError:
        print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")
        return

    targets = [files[i] for i in indices if 0 <= i < len(files)]
    if not targets:
        return

    confirm = input(f"\nMover {len(targets)} arquivo(s) para a Lixeira? (s/N): ").strip().lower()
    if confirm != 's':
        print(f"{Colors.GRAY}Operação cancelada.{Colors.ENDC}")
        return

    freed = 0
    for item in targets:
        success, msg = delete_large_file(item["path"])
        if success:
            freed += item["size_bytes"]
            print(f"  {Colors.GREEN}[Removido]{Colors.ENDC} {item['name']}")
        else:
            print(f"  {Colors.FAIL}[Erro]{Colors.ENDC} {item['name']}: {msg}")

    print(f"\n{Colors.GREEN}✓ {format_size(freed)} movidos para a Lixeira.{Colors.ENDC}")

def menu_duplicates():
    print_header("DETECTOR DE ARQUIVOS DUPLICADOS")
    print(f"{Colors.GRAY}Comparação por tamanho + hash parcial + SHA-256 completo...{Colors.ENDC}")
    print(f"{Colors.BLUE}Escaneando Downloads, Documentos, Desktop e Pictures...{Colors.ENDC}\n")

    groups = scan_duplicates()

    if not groups:
        print(f"\n{Colors.GREEN}✓ Nenhum arquivo duplicado encontrado.{Colors.ENDC}")
        return

    total_waste = sum(g["size_bytes"] * (len(g["files"]) - 1) for g in groups)
    print(f"\nEncontrados {Colors.WARNING}{len(groups)}{Colors.ENDC} grupos de duplicados (espaço desperdiçado: {Colors.WARNING}{format_size(total_waste)}{Colors.ENDC}):\n")

    file_counter = 0
    file_map = {}
    for g_idx, group in enumerate(groups):
        print(f"{Colors.BOLD}{Colors.HEADER}  Grupo {g_idx + 1} — {group['size_human']} cada — SHA-256: {group['hash'][:16]}…{Colors.ENDC}")
        for f_idx, f in enumerate(group["files"]):
            file_counter += 1
            keeper = " (PRESERVADO)" if f_idx == 0 else ""
            color = Colors.GREEN if f_idx == 0 else Colors.GRAY
            print(f"    {color}{file_counter:<4} {f['name']:<30} {f['modified']:<16} {f['path']}{keeper}{Colors.ENDC}")
            file_map[file_counter] = (g_idx, f_idx)
        print()

    print(f"{Colors.BOLD}Instruções:{Colors.ENDC}")
    print("  - O primeiro arquivo de cada grupo é SEMPRE preservado.")
    print("  - Digite números das CÓPIAS que deseja remover (ex: 2,4,6).")
    print("  - Pressione Enter para voltar.")

    user_input = input("\nRemover cópias: ").strip()
    if not user_input:
        return

    try:
        chosen = [int(i.strip()) for i in user_input.split(",") if i.strip()]
    except ValueError:
        print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")
        return

    selections = []
    blocked = []
    for num in chosen:
        entry = file_map.get(num)
        if not entry:
            print(f"{Colors.FAIL}Número {num} inválido.{Colors.ENDC}")
            continue
        g_idx, f_idx = entry
        if f_idx == 0:
            blocked.append(num)
            continue
        selections.append({
            "hash": groups[g_idx]["hash"],
            "path": groups[g_idx]["files"][f_idx]["path"],
        })

    if blocked:
        print(f"{Colors.WARNING}⚠️  Itens {blocked} são cópias preservadas e foram ignorados.{Colors.ENDC}")

    if not selections:
        print(f"{Colors.GRAY}Nenhuma cópia selecionada para remoção.{Colors.ENDC}")
        return

    confirm = input(f"\nMover {len(selections)} cópia(s) para a Lixeira? (s/N): ").strip().lower()
    if confirm != 's':
        print(f"{Colors.GRAY}Operação cancelada.{Colors.ENDC}")
        return

    result = delete_duplicate_files(selections)
    if result["errors"]:
        for err in result["errors"]:
            print(f"  {Colors.WARNING}[Aviso]{Colors.ENDC} {err}")
    print(f"\n{Colors.GREEN}✓ {result['deleted']} cópia(s) removida(s). {format_size(result['bytes_freed'])} liberados.{Colors.ENDC}")

def menu_network():
    print_header("REDE E DNS")

    print(f"\n{Colors.BOLD}Opções:{Colors.ENDC}")
    print(f"  {Colors.CYAN}[1]{Colors.ENDC} 🌐 Diagnóstico de Latência")
    print(f"  {Colors.CYAN}[2]{Colors.ENDC} ⚡ Limpar Cache DNS")
    print(f"  {Colors.CYAN}[3]{Colors.ENDC} Voltar")

    choice = input("\nEscolha: ").strip()

    if choice == '1':
        print(f"\n{Colors.BLUE}Medindo latência de rede...{Colors.ENDC}")
        diag = run_network_diagnostic()
        color_map = {"GREEN": Colors.GREEN, "BLUE": Colors.BLUE, "WARNING": Colors.WARNING, "FAIL": Colors.FAIL}
        color = color_map.get(diag["status_color"], Colors.GRAY)
        print(f"\n  Status: {color}{Colors.BOLD}{diag['status']}{Colors.ENDC}")
        print(f"  Latência: {color}{diag['latency_human']}{Colors.ENDC}")
    elif choice == '2':
        print(f"\n{Colors.BLUE}Limpando cache DNS...{Colors.ENDC}")
        success, msg = flush_dns()
        color = Colors.GREEN if success else Colors.FAIL
        print(f"\n  {color}{msg}{Colors.ENDC}")

def menu_memory():
    print_header("MONITOR DE MEMÓRIA RAM")
    print(f"{Colors.GRAY}Analisando consumo de memória e processos...{Colors.ENDC}")

    stats = get_memory_stats()

    pressure_colors = {"normal": Colors.GREEN, "warning": Colors.WARNING, "critical": Colors.FAIL}
    p_color = pressure_colors.get(stats["pressure_level"], Colors.GRAY)

    print(f"\n{Colors.BOLD}--- Uso de Memória ---{Colors.ENDC}")
    print(f"  Total:        {Colors.BOLD}{stats['total_human']}{Colors.ENDC}")
    print(f"  Em uso:       {Colors.WARNING}{stats['used_human']}{Colors.ENDC} ({stats['percent']}%)")
    print(f"  Disponível:   {Colors.GREEN}{stats['available_human']}{Colors.ENDC}")
    print(f"  Livre:        {stats['free_human']}")
    print(f"  Inativa:      {stats['inactive_human']}")
    print(f"  Wired:        {stats['wired_human']}")
    print(f"  Comprimida:   {stats['compressed_human']}")
    print(f"  Purgável:     {stats['purgeable_human']}")
    print(f"  Pressão:      {p_color}{Colors.BOLD}{stats['pressure_label']}{Colors.ENDC}")

    print(f"\n{Colors.BOLD}--- Top 10 Processos por RAM ---{Colors.ENDC}")
    processes = get_top_ram_processes()

    if not processes:
        print(f"  {Colors.GRAY}Nenhum processo listado.{Colors.ENDC}")
        return

    print(f"{'Nº':<4} {'PID':<8} {'Nome':<25} {'RAM':<12} {'%Mem':<8} Caminho")
    print("-" * 100)
    for idx, proc in enumerate(processes, 1):
        name = proc["name"]
        if len(name) > 25:
            name = name[:22] + "..."
        print(f"{idx:<4} {proc['pid']:<8} {name:<25} {Colors.WARNING}{proc['rss_human']:<12}{Colors.ENDC} {proc['pmem']:<8} {Colors.GRAY}{proc['path']}{Colors.ENDC}")

    print(f"\n{Colors.BOLD}Opções:{Colors.ENDC}")
    print("  - Digite o número de um processo para encerrá-lo (SIGTERM).")
    print("  - Pressione Enter para voltar.")

    user_input = input("\nEscolha: ").strip()
    if not user_input:
        return

    try:
        idx = int(user_input) - 1
        if 0 <= idx < len(processes):
            proc = processes[idx]
            confirm = input(f"Encerrar '{proc['name']}' (PID {proc['pid']})? Dados não salvos podem ser perdidos. (s/N): ").strip().lower()
            if confirm == 's':
                success, msg = kill_process(proc["pid"])
                color = Colors.GREEN if success else Colors.FAIL
                print(f"\n  {color}{msg}{Colors.ENDC}")
            else:
                print(f"{Colors.GRAY}Operação cancelada.{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}Número fora da lista.{Colors.ENDC}")
    except ValueError:
        print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")

def menu_uninstaller():
    print_header("DESINSTALADOR DE APLICATIVOS")
    print(f"{Colors.GRAY}Listando aplicativos de terceiros instalados...{Colors.ENDC}")

    apps = list_installed_apps()

    if not apps:
        print(f"\n{Colors.GREEN}✓ Nenhum aplicativo de terceiros localizado.{Colors.ENDC}")
        return

    print(f"\nEncontrados {Colors.CYAN}{len(apps)}{Colors.ENDC} aplicativos:\n")
    print(f"{Colors.BOLD}{'Nº':<4} | {'Nome':<30} | {'Versão':<10} | {'Tamanho':<10} | Caminho{Colors.ENDC}")
    print("-" * 100)

    for idx, app in enumerate(apps, 1):
        name = app["name"]
        if len(name) > 30:
            name = name[:27] + "..."
        print(f"{idx:<4} | {name:<30} | {app['version']:<10} | {app['size_human']:<10} | {Colors.GRAY}{app['path']}{Colors.ENDC}")

    print("-" * 100)
    print(f"\n{Colors.BOLD}Instruções:{Colors.ENDC}")
    print("  - Digite o número do aplicativo para analisar e desinstalar.")
    print("  - Pressione Enter para voltar.")

    user_input = input("\nEscolha: ").strip()
    if not user_input:
        return

    try:
        idx = int(user_input) - 1
    except ValueError:
        print(f"{Colors.FAIL}Opção inválida.{Colors.ENDC}")
        return

    if idx < 0 or idx >= len(apps):
        print(f"{Colors.FAIL}Número fora da lista.{Colors.ENDC}")
        return

    app = apps[idx]
    print(f"\n{Colors.BOLD}Analisando: {app['name']} v{app['version']} ({app['size_human']}){Colors.ENDC}")
    print(f"{Colors.GRAY}Buscando arquivos de suporte relacionados...{Colors.ENDC}")

    related = get_app_related_files(app["path"], app["bundle_id"], app["name"])

    if related:
        related_size = sum(r["size_bytes"] for r in related)
        print(f"\nEncontrados {Colors.WARNING}{len(related)}{Colors.ENDC} arquivos de suporte ({Colors.WARNING}{format_size(related_size)}{Colors.ENDC}):")
        for r_idx, r in enumerate(related, 1):
            print(f"  {r_idx}. {r['name']} ({r['size_human']}) — {Colors.GRAY}{r['path']}{Colors.ENDC}")
    else:
        print(f"\n{Colors.GRAY}Nenhum arquivo de suporte extra encontrado.{Colors.ENDC}")

    related_paths = [r["path"] for r in related]
    privilege_note = ""
    if app["path"].startswith("/Applications/"):
        privilege_note = "\n  O macOS poderá solicitar a senha de administrador."

    confirm = input(f"\nDesinstalar '{app['name']}' e {len(related)} arquivo(s) de suporte?{privilege_note} (s/N): ").strip().lower()
    if confirm != 's':
        print(f"{Colors.GRAY}Operação cancelada.{Colors.ENDC}")
        return

    print(f"\n{Colors.BLUE}Desinstalando {app['name']}...{Colors.ENDC}")
    success, logs = uninstall_app(app["path"], related_paths)
    for log in logs:
        print(f"  {log}")

    if success:
        print(f"\n{Colors.GREEN}✓ Desinstalação concluída com sucesso!{Colors.ENDC}")
    else:
        print(f"\n{Colors.FAIL}✗ Desinstalação concluída com erros.{Colors.ENDC}")

def main():
    try:
        while True:
            clear_screen()
            show_main_menu()
            choice = input(f"{Colors.BOLD}Selecione uma opção (0-11): {Colors.ENDC}").strip()

            if choice == '1':
                clear_screen()
                menu_junk_cleaner()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '2':
                clear_screen()
                menu_app_leftovers()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '3':
                clear_screen()
                menu_dependencies()
            elif choice == '4':
                clear_screen()
                menu_startup()
            elif choice == '5':
                clear_screen()
                menu_large_files()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '6':
                clear_screen()
                menu_duplicates()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '7':
                clear_screen()
                menu_network()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '8':
                clear_screen()
                menu_memory()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '9':
                clear_screen()
                menu_uninstaller()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '10':
                clear_screen()
                menu_browser_caches()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '11':
                clear_screen()
                menu_security_audit()
                input("\nPressione Enter para voltar ao menu principal...")
            elif choice == '0':
                print(
                    f"\n{Colors.BLUE}Obrigado por usar o {APP_NAME} CLI! Até logo. "
                    f"⚡{Colors.ENDC}\n"
                )
                break
            else:
                print(f"\n{Colors.FAIL}Opção inválida. Por favor, escolha um número de 0 a 11.{Colors.ENDC}")
                input("\nPressione Enter para continuar...")
    except KeyboardInterrupt:
        print(f"\n\n{Colors.BLUE}Processo encerrado pelo usuário. Até logo! ⚡{Colors.ENDC}\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
