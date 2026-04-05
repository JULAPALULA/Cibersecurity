/*
*   main.rs - Encriptación y desencriptación AES-256 (CBC, OFB, CFB, ECB)
*   @author nombre_apellidos
*   @date 05/04/2026
*   @version 1.0
*
*   Práctica 4 para el curso de Ciberseguridad de TokioSchool.
*   Cifrado simétrico AES-256 aplicado en cuatro modos de operación:
*   CBC, OFB, CFB y ECB, con verificación de descifrado en cada uno.
*
*   // =============================================================
*   //   CIFRADO AES-256
*   //   Texto : ESTAMOS EN CLASE DE CRIPTOGRAFIA
*   //   Clave : 12345678901234567890123456789012  (32 bytes -> AES-256)
*   //   Modos : CBC, OFB, CFB, ECB
*   // =============================================================
*   //
*   //  ¿Qué es AES?
*   //  AES (Advanced Encryption Standard) es un cifrado de bloque:
*   //  divide el texto en bloques de 16 bytes y los cifra con una
*   //  clave. Con una clave de 32 bytes usamos AES-256.
*   //
*   //  ¿Qué es un modo de operación?
*   //  AES solo sabe cifrar un bloque de 16 bytes. Los modos de
*   //  operación definen CÓMO se encadenan esos bloques cuando el
*   //  mensaje es más largo.
*   //
*   //   BLOQUE 1   BLOQUE 2   BLOQUE 3
*   //  [ESTAMOS ] [EN CLASE ] [DE CRIPT]  <-- texto dividido
*   //      |           |           |
*   //    AES(k)     AES(k)      AES(k)    <-- cada bloque se cifra
*   //      |           |           |
*   //  [??????? ] [???????? ] [????????]  <-- criptograma
*   //
*   //  El modo decide si los bloques se "hablan" entre sí (CBC, OFB,
*   //  CFB) o si cada uno va por su cuenta (ECB).
*   //
*   // =============================================================
*/

use aes::Aes256;
use base64::{engine::general_purpose, Engine as _};
use cipher::{
    block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit,
};
use rand::RngCore;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256OfbEnc = ofb::Ofb<Aes256>;
type Aes256CfbEnc = cfb_mode::Encryptor<Aes256>;
type Aes256CfbDec = cfb_mode::Decryptor<Aes256>;
type Aes256EcbEnc = ecb::Encryptor<Aes256>;
type Aes256EcbDec = ecb::Decryptor<Aes256>;


const TEXTO: &str = "ESTAMOS EN CLASE DE CRIPTOGRAFIA";
const CLAVE: &[u8; 32] = b"12345678901234567890123456789012";

// =============================================================
//  UTILIDADES
// =============================================================

/*
*   Genera un IV (Vector de Inicialización) aleatorio de 16 bytes.
*
*   ¿Qué es el IV?
*   Es un valor aleatorio que se usa como "semilla" al inicio del
*   cifrado. Gracias a él, cifrar el mismo texto dos veces produce
*   criptogramas distintos aunque la clave sea igual.
*
*       Ejecución 1:  IV = a3f1...  ->  CT = 9c2b...
*       Ejecución 2:  IV = 77de...  ->  CT = f041...
*                          ^^^^              ^^^^
*                          diferente          diferente!
*
*   Returns:
*       [u8; 16] -> Array de 16 bytes aleatorios
*/
fn iv_aleatorio() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv); // equivalente a os.urandom(16) en Python
    iv
}

/*
*   Imprime una línea separadora con título centrado.
*
*   Args:
*       titulo -> Texto que aparece en el separador
*/
fn imprimir_separador(titulo: &str) {
    println!("\n{}", "*".repeat(62));
    println!("  {}", titulo);
    println!("{}", "*".repeat(62));
}

/*
*   Imprime el criptograma en formato hexadecimal y Base64.
*
*   ¿Por qué dos formatos?
*   - Hex:    cada byte -> 2 dígitos hexadecimales (0-9, a-f). Legible.
*   - Base64: comprime la representación usando 64 caracteres.
*
*   Ejemplo:
*       bytes  = [0x4e, 0x2b, 0x1f]
*       hex    = "4e2b1f"
*       base64 = "Tisfj..."
*
*   Args:
*       etiqueta -> Prefijo impreso (p.ej. "IV" o "CT")
*       bytes    -> Datos binarios a mostrar
*/
fn imprimir_resultado(etiqueta: &str, bytes: &[u8]) {
    println!("  {:6} hex : {}", etiqueta, hex::encode(bytes));
    println!("  {:6} b64 : {}", etiqueta, general_purpose::STANDARD.encode(bytes));
}

// =============================================================
//  MODO CBC — Cipher Block Chaining
// =============================================================
//
//  ¿Cómo funciona CBC?
//
//  Cada bloque de texto plano se combina (XOR) con el bloque
//  cifrado anterior ANTES de ser cifrado por AES.
//  El primer bloque se combina con el IV.
//
//  CIFRADO:
//
//   IV ──┐
//        XOR <- [Bloque 1 texto]
//        │
//      AES(k)
//        │
//   [Bloque 1 CT] ──┐
//                   XOR <- [Bloque 2 texto]
//                   │
//                 AES(k)
//                   │
//              [Bloque 2 CT] -> ...
//
//  DESCIFRADO: proceso inverso (AES decrypt + XOR con CT anterior)
//
//  Ventaja:  bloques iguales en el texto -> CT siempre diferente
//  Ventaja:  IV aleatorio -> cada ejecución produce un CT distinto
//  Desventaja: no se puede paralelizar el cifrado (sí el descifrado)
// =============================================================

/*
*   Cifra texto con AES-256 en modo CBC.
*
*   Se aplica relleno PKCS#7 automáticamente para completar el
*   último bloque hasta 16 bytes si el texto no es múltiplo de 16.
*
*   ¿Qué es PKCS#7?
*   Si faltan N bytes para completar el bloque, se añaden N bytes
*   con el valor N:
*
*       Texto:    [ E S T A M O S ]                   (7 bytes)
*       Relleno:  [ E S T A M O S 09 09 09 09 09 09 09 09 09 ]
*                                  ^--- faltan 9, se añaden nueve 0x09
*
*   Args:
*       texto -> Bytes del texto plano
*       clave -> Clave AES de 32 bytes (AES-256)
*       iv    -> Vector de Inicialización de 16 bytes
*   Returns:
*       Vec<u8> -> Criptograma como vector de bytes
*/
fn cifrar_cbc(texto: &[u8], clave: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    Aes256CbcEnc::new(clave.into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(texto)
}

/*
*   Descifra un criptograma AES-256-CBC.
*
*   Necesita el mismo IV que se usó al cifrar.
*   Si el IV o la clave son incorrectos, el texto descifrado
*   será basura (o pánico si el relleno es inválido).
*
*   Args:
*       ct    -> Criptograma (bytes cifrados)
*       clave -> Clave AES de 32 bytes
*       iv    -> Mismo IV usado al cifrar
*   Returns:
*       Vec<u8> -> Texto plano recuperado
*/
fn descifrar_cbc(ct: &[u8], clave: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    Aes256CbcDec::new(clave.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .expect("Error al descifrar CBC: IV/clave incorrectos o CT corrupto")
}

// =============================================================
//  MODO OFB — Output Feedback
// =============================================================
//
//  ¿Cómo funciona OFB?
//
//  AES cifra el IV para generar un "flujo de clave" (keystream).
//  Ese flujo se combina (XOR) con el texto plano.
//  AES nunca toca el texto directamente: actúa como generador
//  de números pseudoaleatorios.
//
//  CIFRADO:
//
//   IV -> AES(k) -> S1 -> AES(k) -> S2 -> AES(k) -> S3 ...
//                  |              |              |
//                 XOR            XOR            XOR
//                  |              |              |
//              [CT bloque 1] [CT bloque 2] [CT bloque 3]
//
//  Ventaja:  errores de transmisión no se propagan entre bloques
//  Ventaja:  el keystream se puede precomputar
//  Desventaja: NO se puede paralelizar (cada S depende del anterior)
// =============================================================

/*
*   Cifra texto con AES-256 en modo OFB.
*
*   OFB usa el trait StreamCipher (cifrado de flujo), no
*   BlockEncryptMut. Por eso aplicamos el relleno PKCS#7
*   manualmente antes de llamar a apply_keystream().
*
*   ¿Qué hace apply_keystream()?
*   Genera el flujo de clave y hace XOR byte a byte con el
*   buffer que se le pasa. Modifica el buffer en su sitio (in-place).
*
*   Args:
*       texto -> Bytes del texto plano
*       clave -> Clave AES de 32 bytes
*       iv    -> Vector de Inicialización de 16 bytes
*   Returns:
*       Vec<u8> -> Criptograma como vector de bytes
*/
fn cifrar_ofb(texto: &[u8], clave: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    use cipher::StreamCipher;

    // Copiamos el texto y añadimos relleno PKCS#7 manualmente
    //
    //  pad_len = bytes que faltan para llegar al siguiente múltiplo de 16
    //
    //  Ejemplo: texto de 32 bytes  ->  pad_len = 16 - (32 % 16) = 16
    //           texto de 7 bytes   ->  pad_len = 16 - (7  % 16) = 9
    //
    //  PKCS#7: rellenamos con N bytes de valor N
    //   [... 09 09 09 09 09 09 09 09 09]   (9 bytes con valor 0x09)
    let mut ct = texto.to_vec();
    let pad_len = 16 - (ct.len() % 16);
    ct.extend(vec![pad_len as u8; pad_len]);

    // Aplicamos el keystream OFB sobre el buffer (modifica en su sitio)
    let mut cipher = Aes256OfbEnc::new(clave.into(), iv.into());
    cipher.apply_keystream(&mut ct);
    ct
}

/*
*   Descifra un criptograma AES-256-OFB.
*
*   OFB es simétrico: cifrar y descifrar usan la misma operación
*   (XOR con el mismo keystream). Por eso reutilizamos la misma
*   lógica y luego eliminamos el relleno PKCS#7.
*
*   Args:
*       ct    -> Criptograma (bytes cifrados)
*       clave -> Clave AES de 32 bytes
*       iv    -> Mismo IV usado al cifrar
*   Returns:
*       Vec<u8> -> Texto plano recuperado
*/
fn descifrar_ofb(ct: &[u8], clave: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    use cipher::StreamCipher;

    let mut pt = ct.to_vec();
    let mut cipher = Aes256OfbEnc::new(clave.into(), iv.into());
    cipher.apply_keystream(&mut pt); // mismo XOR -> recupera el texto

    // Eliminamos el relleno PKCS#7
    //
    //  El último byte del texto descifrado indica cuántos bytes
    //  de relleno hay que quitar:
    //
    //   [..., 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09]
    //                                                              ^
    //                                                     pad = 9 bytes
    //   truncate(len - 9)  ->  queda solo el texto original
    let pad = *pt.last().unwrap() as usize;
    pt.truncate(pt.len() - pad);
    pt
}

// =============================================================
//  MODO CFB — Cipher Feedback
// =============================================================
//
//  ¿Cómo funciona CFB?
//
//  Similar a OFB, pero el keystream se genera cifrando el
//  CRIPTOGRAMA anterior (no el keystream anterior como en OFB).
//
//  CIFRADO:
//
//   IV -> AES(k) -> XOR <- [Bloque 1 texto]
//                  |
//              [CT bloque 1] -> AES(k) -> XOR <- [Bloque 2 texto]
//                                         |
//                                     [CT bloque 2] -> ...
//
//  Diferencia con OFB: el feedback viene del CT (no del keystream).
//  Esto hace que un error en transmisión afecte al bloque siguiente.
//
//  Ventaja:  IV aleatorio -> CT siempre distinto por ejecución
//  Desventaja: no paralelizable en cifrado (sí en descifrado)
// =============================================================

/*
*   Cifra texto con AES-256 en modo CFB.
*
*   Args:
*       texto -> Bytes del texto plano
*       clave -> Clave AES de 32 bytes
*       iv    -> Vector de Inicialización de 16 bytes
*   Returns:
*       Vec<u8> -> Criptograma como vector de bytes
*/
fn cifrar_cfb(texto: &[u8], clave: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    Aes256CfbEnc::new(clave.into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(texto)
}

/*
*   Descifra un criptograma AES-256-CFB.
*
*   Args:
*       ct    -> Criptograma (bytes cifrados)
*       clave -> Clave AES de 32 bytes
*       iv    -> Mismo IV usado al cifrar
*   Returns:
*       Vec<u8> -> Texto plano recuperado
*/
fn descifrar_cfb(ct: &[u8], clave: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    Aes256CfbDec::new(clave.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .expect("Error al descifrar CFB: IV/clave incorrectos o CT corrupto")
}

// =============================================================
//  MODO ECB — Electronic Codebook
// =============================================================
//
//  ¿Cómo funciona ECB?
//
//  Cada bloque de 16 bytes se cifra DE FORMA INDEPENDIENTE
//  con la misma clave. No hay encadenamiento ni IV.
//
//  CIFRADO:
//
//  [Bloque 1] -> AES(k) -> [CT 1]
//  [Bloque 2] -> AES(k) -> [CT 2]   <- misma clave, sin IV
//  [Bloque 3] -> AES(k) -> [CT 3]
//
//  * PROBLEMA GRAVE:
//  Si dos bloques de texto plano son iguales, sus criptogramas
//  también serán iguales. Esto revela patrones del texto original.
//
//  Ejemplo famoso: una imagen cifrada con ECB sigue siendo
//  reconocible porque los bloques de color uniforme producen
//  bloques de CT idénticos -> la forma se preserva visualmente.
//
//  * ECB NO debe usarse en aplicaciones reales.
// =============================================================

/*
*   Cifra texto con AES-256 en modo ECB.
*
*   Nótese que NO recibe IV: ECB no usa vector de inicialización.
*   Esto hace que el resultado sea siempre idéntico para la misma
*   combinación de texto + clave.
*
*   Args:
*       texto -> Bytes del texto plano
*       clave -> Clave AES de 32 bytes
*   Returns:
*       Vec<u8> -> Criptograma como vector de bytes
*/
fn cifrar_ecb(texto: &[u8], clave: &[u8; 32]) -> Vec<u8> {
    Aes256EcbEnc::new(clave.into())
        .encrypt_padded_vec_mut::<Pkcs7>(texto)
}

/*
*   Descifra un criptograma AES-256-ECB.
*
*   Args:
*       ct    -> Criptograma (bytes cifrados)
*       clave -> Clave AES de 32 bytes
*   Returns:
*       Vec<u8> -> Texto plano recuperado
*/
fn descifrar_ecb(ct: &[u8], clave: &[u8; 32]) -> Vec<u8> {
    Aes256EcbDec::new(clave.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .expect("Error al descifrar ECB: clave incorrecta o CT corrupto")
}

//  MAIN

fn main() {
    let texto_bytes = TEXTO.as_bytes();

    println!("  Texto : {}", TEXTO);
    println!("  Clave : {}", std::str::from_utf8(CLAVE).unwrap());
    println!("  Longitud clave : {} bytes -> AES-256", CLAVE.len());

    // CBC
    imprimir_separador("MODO CBC – Cipher Block Chaining");

    // Guardamos IV y CT de la ejecución 1 para verificar el descifrado
    let mut cbc_iv_guardado = [0u8; 16];
    let mut cbc_ct_guardado = Vec::new();

    for i in 1..=3 {
        let iv = iv_aleatorio(); // nuevo IV aleatorio en cada iteración
        let ct = cifrar_cbc(texto_bytes, CLAVE, &iv);

        println!("\n  Ejecución {}:", i);
        imprimir_resultado("IV", &iv);
        imprimir_resultado("CT", &ct);

        if i == 1 {
            cbc_iv_guardado = iv;
            cbc_ct_guardado = ct;
        }
    }

    // Verificación: desciframos con el IV y CT de la ejecución 1
    // El resultado debe ser idéntico al texto original
    println!("\n[Verificación descifrado (ejecución 1)]");
    let pt_cbc = descifrar_cbc(&cbc_ct_guardado, CLAVE, &cbc_iv_guardado);
    let recuperado = std::str::from_utf8(&pt_cbc).unwrap();
    println!("  Texto descifrado : {}", recuperado);
    println!(
        "  ¿Coincide?       : {}",
        if recuperado == TEXTO { "SÍ" } else { "NO" }
    );

    // OFB
    imprimir_separador("MODO OFB – Output Feedback");

    let mut ofb_iv_guardado = [0u8; 16];
    let mut ofb_ct_guardado = Vec::new();

    for i in 1..=3 {
        let iv = iv_aleatorio();
        let ct = cifrar_ofb(texto_bytes, CLAVE, &iv);

        println!("\n  Ejecución {}:", i);
        imprimir_resultado("IV", &iv);
        imprimir_resultado("CT", &ct);

        if i == 1 {
            ofb_iv_guardado = iv;
            ofb_ct_guardado = ct;
        }
    }

    println!("\n[Verificación descifrado (ejecución 1)]");
    let pt_ofb = descifrar_ofb(&ofb_ct_guardado, CLAVE, &ofb_iv_guardado);
    let recuperado = std::str::from_utf8(&pt_ofb).unwrap();
    println!("  Texto descifrado : {}", recuperado);
    println!(
        "  ¿Coincide?       : {}",
        if recuperado == TEXTO { "SÍ" } else { "NO" }
    );

    // CFB
    imprimir_separador("MODO CFB – Cipher Feedback");

    let mut cfb_iv_guardado = [0u8; 16];
    let mut cfb_ct_guardado = Vec::new();

    for i in 1..=3 {
        let iv = iv_aleatorio();
        let ct = cifrar_cfb(texto_bytes, CLAVE, &iv);

        println!("\n  Ejecución {}:", i);
        imprimir_resultado("IV", &iv);
        imprimir_resultado("CT", &ct);

        if i == 1 {
            cfb_iv_guardado = iv;
            cfb_ct_guardado = ct;
        }
    }

    println!("\n[Verificación descifrado (ejecución 1)]");
    let pt_cfb = descifrar_cfb(&cfb_ct_guardado, CLAVE, &cfb_iv_guardado);
    let recuperado = std::str::from_utf8(&pt_cfb).unwrap();
    println!("  Texto descifrado : {}", recuperado);
    println!(
        "  ¿Coincide?       : {}",
        if recuperado == TEXTO { "SÍ" } else { "NO" }
    );

    // ECB 
    imprimir_separador("MODO ECB – Electronic Codebook  * Sin IV");

    // En ECB no hay IV. Guardamos solo el CT de la primera ejecución.
    let mut ecb_ct_guardado = Vec::new();

    for i in 1..=3 {
        let ct = cifrar_ecb(texto_bytes, CLAVE);

        println!("\n  Ejecución {}:", i);
        println!("  IV     : (ninguno – ECB no usa IV)");
        imprimir_resultado("CT", &ct);

        if i == 1 {
            ecb_ct_guardado = ct;
        }
    }

    // Las 3 ejecuciones producen exactamente el mismo CT porque
    // ECB es determinista: sin IV, la salida solo depende de la clave.
    println!("\n  *  Las 3 ejecuciones producen EXACTAMENTE el mismo CT.");
    println!("     ECB es determinista: igual texto + igual clave = igual CT siempre.");

    println!("\n  ── Verificación descifrado (ejecución 1) ──");
    let pt_ecb = descifrar_ecb(&ecb_ct_guardado, CLAVE);
    let recuperado = std::str::from_utf8(&pt_ecb).unwrap();
    println!("  Texto descifrado : {}", recuperado);
    println!(
        "  ¿Coincide?       : {}",
        if recuperado == TEXTO { "SÍ" } else { "NO" }
    );

    println!("\n{}", "─".repeat(62));
    println!("  CONCLUSIÓN");
    println!("{}", "─".repeat(62));
    println!("  CBC, OFB, CFB  ->  IV aleatorio  ->  CT distinto en cada ejecución");
    println!("  ECB            ->  sin IV        ->  CT idéntico siempre  * inseguro");
    println!("  Todos los modos descifran correctamente el texto original.\n");
}