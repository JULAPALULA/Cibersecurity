/*
*   main.rs - Encriptación y desencriptación Vigenère
*   @author Jorge J. Álvarez García
*   @date 22/03/2026
*   @version 1.0
*
*   Prueba para el curso de Ciberseguridad de TokioSchool para la encriptación y 
*   desencriptación del cifrado Vigenère.
*
*   // =============================================================
*   //   CIFRADO DE VIGENÈRE
*   //   Texto : ESTAMOS EN CLASE DE CRIPTOGRAFIA
*   //   Clave : ESTOY USANDO UNA CLAVE ALEATORIA PARA EL CIFRADO
*   // =============================================================
*   //
*   //  ¿Qué es el cifrado de Vigenère?
*   //  Es como el cifrado César, pero en lugar de desplazar todas
*   //  las letras el mismo número, cada letra se desplaza un número
*   //  DIFERENTE dependiendo de la letra de la clave.
*   //
*   //   TEXTO:  E  S  T  A  M  O  S  ...
*   //   CLAVE:  E  S  T  O  Y  U  S  ...  <-- cada letra da un desplazamiento
*   //           |  |  |  |  |  |  |
*   //           v  v  v  v  v  v  v
*   //  CIFRADO: I  K  M  O  K  I  K  ...
*   //
*   // =============================================================
*   
*   Referencia útil: https://www.dcode.fr/cifrado-vigenere
*/

/*
*   Función para encriptar texto según el cifrado Vigenère.
*
*   Args:
*       text -> Texto limpio (simplificado)
*       key -> Clave (simplificado)
*   Returns:
*       result -> Texto encriptado
*/
fn vigenere_encrypt(text: &str, key: &str) -> String {
    
    // Limpiar el texto
    // Quitamos espacios y signos, y ponemos todo en MAYUSCULAS
    //
    //  Entrada:  "ESTAMOS EN CLASE"
    //             ^      ^^      ^--- espacios que se eliminan
    //  Salida:   "ESTAMOSENCLASE"
    let text_clean: Vec<char> = text
        .chars()
        .filter(|c| c.is_ascii_alphabetic()) // solo letras A-Z
        .map(|c| c.to_ascii_uppercase())     // todo a mayúsculas
        .collect();

    let key_clean: Vec<char> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic()) // solo letras A-Z
        .map(|c| c.to_ascii_uppercase())     // todo a mayúsculas
        .collect();

     // Si la clave quedo vacía, no podemos cifrar nada
    if key_clean.is_empty() {
        panic!("La clave no puede estar vacía.");
    }

    
    let mut result = String::new();
    let key_len = key_clean.len(); // longitud de la clave limpia

    //  text_clean = [ 'E', 'S', 'T', 'A', 'M', ... ]
    //                  ^     ^
    //                  |     |
    //   i=0, c='E'  ---+     |
    //   i=1, c='S'  ---------+
    //   ...
    //
    //  .enumerate() nos da la pareja (indice, letra)
    //  El & en &c "desenvuelve" la referencia para tener el char directamente
    for (i, &c) in text_clean.iter().enumerate() {

        //  Alfabeto:  A  B  C  D  E  F  G  H  I  J  K ... Z
        //  Indice:    0  1  2  3  4  5  6  7  8  9  10... 25
        //
        //  Truco: restamos el codigo ASCII de 'A' (que es 65)
        //
        //   'E' tiene codigo ASCII 69
        //    69 - 65 = 4   =>  p = 4
        //
        //    [ASCII]   E=69
        //              menos
        //    [ASCII]   A=65
        //              -----
        //              p = 4

        let p = (c as u8 - b'A') as u32;

        //  La clave se "recicla" con el operador % (modulo):
        //  si el texto tiene mas letras que la clave, volvemos
        //  al principio de la clave.
        //
        //  Ejemplo con clave de 5 letras [E,S,T,O,Y]:
        //
        //  texto pos:  0  1  2  3  4  5  6  7  8  9 ...
        //  clave pos:  0  1  2  3  4  0  1  2  3  4 ...
        //                              ^----- vuelve a empezar!
        //
        //  i % key_len  =>  nos da la posicion correcta en la clave
        //
        //  Luego convertimos esa letra a numero igual que antes:
        //   'E' => 4

        let k = (key_clean[i % key_len] as u8 - b'A') as u32;

        //   Formula:  C = (p + k) % 26
        //
        //   Ejemplo: texto='E'(4) + clave='E'(4)
        //
        //   Alfabeto circular:
        //   A B C D [E] F G H [I] J K L M N O P Q R S T U V W X Y Z
        //   0 1 2 3  4  5 6 7  8  ...
        //            ^           ^
        //            |           |
        //       empezamos      llegamos tras
        //       en 'E'=4       4 pasos => 'I'=8
        //
        //   Para que sirve el % 26?
        //   Si la suma pasa de 25, "da la vuelta" al alfabeto:
        //
        //   ... X  Y  Z  A  B  C ...
        //      23 24 25  0  1  2
        //               ^--- despues de Z viene A otra vez!
        //
        //   Z(25) + 2 = 27  =>  27 % 26 = 1  =>  'B'  correcto!
        //   (sin % daría un caracter raro fuera del alfabeto)
        //
        //   Por ultimo, sumamos b'A' (65) para volver a ASCII:
        //   8 + 65 = 73  =>  'I'
        let encrypted = ((p + k) % 26) as u8 + b'A';

        // Guardamos la letra cifrada en el resultado
        result.push(encrypted as char); 
    }

    result // devolvemos el texto cifrado
}

fn vigenere_decrypt(ciphertext: &str, key: &str) -> String {

     // Igual que en cifrado: limpiar y poner en mayúsculas
    let cipher_clean: Vec<char> = ciphertext
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let key_clean: Vec<char> = key
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if key_clean.is_empty() {
        panic!("La clave no puede estar vacía.");
    }

    let mut result = String::new();
    let key_len = key_clean.len();

     // Recorremos cada letra del texto cifrado
    for (i, &c) in cipher_clean.iter().enumerate() {

        //  Convertimos la letra cifrada a número (igual que antes)
        let p = (c as u8 - b'A') as u32;

        // Obtenemos la letra de la clave (igual que antes)
        let k = (key_clean[i % key_len] as u8 - b'A') as u32;

        // DESCIFRAR: formula inversa
        //
        //  Cifrar   era:  C = (p + k) % 26   => avanzamos k pasos
        //  Descifrar es:  P = (C - k + 26) % 26 => retrocedemos k pasos
        //
        //  Ejemplo: cifrado='I'(8), clave='E'(4)
        //
        //   Alfabeto (yendo hacia atrás):
        //   A B C D [E] F G H [I] J ...
        //   0 1 2 3  4  5 6 7  8
        //            ^           ^
        //            |           |
        //         llegamos    empezamos
        //         a 'E'=4     en 'I'=8
        //                     retrocedemos 4
        //
        //  Por que sumamos +26?
        //  Porque p y k son u32 (sin signo negativo).
        //  Si k > p, la resta daría un número negativo => error!
        //
        //   Ejemplo peligroso: cifrado='B'(1), clave='E'(4)
        //
        //    sin +26:   1 - 4 = -3  <== u32 no puede ser negativo! CRASH
        //    con +26:   1 - 4 + 26 = 23  =>  23 % 26 = 23  =>  'X'  ok!
        //
        //  Sumar 26 (una vuelta completa al alfabeto) no cambia
        //  el resultado matemático, pero evita el numero negativo.
        // -----------------------------------------------------
        let decrypted = ((p + 26 - k) % 26) as u8 + b'A';
        result.push(decrypted as char);
    }

    result
}

fn main() {
    let texto = "ESTAMOS EN CLASE DE CRIPTOGRAFIA";
    let clave = "ESTOY USANDO UNA CLAVE ALEATORIA PARA EL CIFRADO";

    println!("=== Cifrado de Vigenère ===\n");
    println!("Texto original : {}", texto);
    println!("Clave          : {}", clave);

    let texto_limpio: String = texto.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let clave_limpia: String = clave.chars().filter(|c| c.is_ascii_alphabetic()).collect();

    println!("\n--- Alineación texto / clave ---");
    let key_chars: Vec<char> = clave_limpia.chars().collect();
    let key_len = key_chars.len();
    let text_chars: Vec<char> = texto_limpio.chars().collect();
    
    print!("Texto : ");
    for c in &text_chars { print!("{} ", c); }
    println!();
    print!("Clave : ");
    for (i, _) in text_chars.iter().enumerate() {
        print!("{} ", key_chars[i % key_len]);
    }
    println!();

    let cifrado = vigenere_encrypt(texto, clave);
    println!("\nTexto cifrado  : {}", cifrado);

    let descifrado = vigenere_decrypt(&cifrado, clave);
    println!("Texto descifrado: {}", descifrado);
}