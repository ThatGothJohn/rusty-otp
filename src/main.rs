use std::io::{Write, stdout};

use crossterm::{execute, ExecutableCommand, cursor, Result};


fn main() -> Result<()>{
    let mut stdout = stdout();
    println!("dirt");
    execute!(stdout, cursor::MoveUp(1))?;
    println!("Bang!, and the dirt is gone.");
    Ok(())
}
