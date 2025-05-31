from rich.console import Console

console = Console(highlight=False)
status = None
mode = "SCANNING"
color = 'cyan'
attack = ''


def log_info(msg):
    console.print(f"[bold green]INFO[/bold green] | {msg}")
    
def log_success(msg):
    console.print(f"[bold green]SUCCESS[/bold green] | {msg}")

def log_error(msg):
    console.print(f"[bold red]ERROR[/bold red] | {msg}")
    
def log_warning(msg):
    console.print(f"[bold yellow]WARNING[/bold yellow] | {msg}")
    
def log_debug(msg):
    console.log(f"[bold blue]DEBUG[/bold blue] | {msg}")
    
def log_attack(msg):
    console.rule(f"[bold yellow]ATTACK[/bold yellow] | {msg}", align="left") 
    console.print()
    
def log_vulnerability(level, msg):
    
    level = level.lower()
    if level == 'low':
        console.print(f"[bold blue]LOW[/bold blue] | [white]{msg}[/white]")
    elif level == 'medium':
        console.print(f"[bold yellow]MEDIUM[/bold yellow] | [white]{msg}[/white]")
    elif level == 'high':
        console.print(f"[bold red]HIGH[/bold red] | [white]{msg}[/white]")
    elif level == 'critical':
        console.print(f"[bold black on red]CRITICAL[/bold black on red] | [white]{msg}[/white]")
        
def log_detail(msg1, msg2 = None):
    if msg1 in '' and msg2 is None:
        console.print()
        return
    console.print(f'{msg1:<10} : {msg2}')  


def status_start():
    global status
    status = console.status(f"[{color}]{mode} {attack} | initializing...", spinner="arc")
    status.__enter__()

def status_update(msg: str):
    if status:
        status.update(f"[{color}]{mode} {attack} | {msg}")

def status_attack_start():
    global status
    global mode
    global color
    mode = "ATTACKING"
    color = 'yellow'
    status.update(f"[{color}]{mode} {attack} | initializing...")
    
def status_update_attack(mod):
    global attack
    attack = mod
    
def status_stop():
    global status
    if status:
        status.__exit__(None, None, None)
        status = None


