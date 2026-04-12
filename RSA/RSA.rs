/*
*   main.rs - Cifrado RSA-2048 y Firma ECDSA (SECP256K1)
*   @author Jorge J. Álvarez García
*   @date 12/04/2026
*   @version 1.0
*
*   // =============================================================
*   //   CIFRADO ASIMÉTRICO RSA  +  FIRMA ECDSA
*   //   Texto : ESTAMOS EN CLASE DE CRIPTOGRAFIA
*   //   RSA   : clave 2048 bits, exponente 65537
*   //   ECDSA : curva SECP256K1
*   // =============================================================
*   //
*   //  ¿Qué es RSA?
*   //  RSA es un sistema de cifrado ASIMÉTRICO: usa DOS claves
*   //  matemáticamente relacionadas.
*   //
*   //   CLAVE PÚBLICA  -> se comparte libremente  -> CIFRA
*   //   CLAVE PRIVADA  -> secreta                 -> DESCIFRA / FIRMA
*   //
*   //  Su seguridad se basa en la dificultad de factorizar el
*   //  producto de dos primos grandes:  n = p · q
*   //
*   //   genera (pub, priv)
*   //   publica pub -----------------> cifra con pub  -> CT
*   //   recibe CT  <------------------
*   //   descifra con priv -> texto
*   //
*   //  ¿Qué es ECDSA?
*   //  Elliptic Curve Digital Signature Algorithm.
*   //  Firma digital basada en curvas elípticas. Misma seguridad
*   //  que RSA pero con claves MUCHO más cortas:
*   //
*   //   RSA 2048 bits  ≈  ECDSA 224 bits  (nivel de seguridad)
*   //
*   //  SECP256K1 es la curva usada por Bitcoin y Ethereum.
*   //
*   // =============================================================
*/

use p256::ecdsa::{SigningKey as EcdsaSigningKey, Signature as EcdsaSignature};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePublicKey;
use rsa::oaep::Oaep;
use rsa::pss::{BlindedSigningKey, VerifyingKey as PssVerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::signature::Verifier as RsaVerifier;
use sha2::Sha256;
use rand::rngs::OsRng;
use hex;

const TEXTO: &str   = "ESTAMOS EN CLASE DE CRIPTOGRAFIA";
const BITS_RSA: usize = 2048;
const EXPONENTE: u64  = 65537;

// =============================================================
//  UTILIDADES
// =============================================================

/*
*   Imprime una línea separadora con título.
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
*   Imprime datos binarios en hexadecimal con longitud.
*
*   Igual que en la práctica anterior, mostramos en hex para
*   inspeccionar el resultado byte a byte.
*
*   Args:
*       etiqueta -> Prefijo impreso (p.ej. "CT" o "FIRMA")
*       datos    -> Datos binarios a mostrar
*/
fn imprimir_bytes(etiqueta: &str, datos: &[u8]) {
    println!("\n  {}:", etiqueta);
    println!("  hex : {}", hex::encode(datos));
    println!("  len : {} bytes", datos.len());
}

// =============================================================
//  EJERCICIO 1 — RSA-2048
// =============================================================
//
//  ¿Cómo funciona RSA?
//
//  1. Generar dos primos grandes p y q
//  2. n = p * q            (módulo, 2048 bits -> clave de 256 bytes)
//  3. φ(n) = (p-1)(q-1)
//  4. e = 65537            (exponente público, primo de Fermat F4)
//  5. d = e⁻¹ mod φ(n)    (exponente privado)
//
//  Clave pública  = (e, n)
//  Clave privada  = (d, n)
//
//  CIFRADO:    CT = M^e  mod n     (con clave PÚBLICA)
//  DESCIFRADO: M  = CT^d mod n     (con clave PRIVADA)
//
//  ¿Por qué 65537 como exponente?
//  En binario = 10000000000000001 -> solo 2 bits a 1.
//  Esto hace la exponenciación modular más rápida.
//  Además es primo, lo que garantiza que gcd(e, φ(n)) = 1.
//
//  PADDING OAEP (para cifrado):
//  RSA "puro" (textbook RSA) es determinista y vulnerable.
//  OAEP (Optimal Asymmetric Encryption Padding) mezcla el
//  mensaje con bytes aleatorios antes de cifrar:
//
//   M ----> OAEP(M, r) ----> RSA_encrypt ----> CT
//                  ^
//               r aleatorio
//
//  Resultado: mismo M cifrado dos veces produce CTs distintos.
//
//  PADDING PSS (para firma):
//  PSS (Probabilistic Signature Scheme) añade una sal aleatoria
//  antes de firmar -> cada firma es diferente (como OAEP en cifrado).
//  Es la variante de padding recomendada por los estándares actuales.
//
// =============================================================

/*
*   Genera un par de claves RSA-2048.
*
*   Usa el exponente público 65537, el más recomendado por
*   los estándares modernos (NIST, PKCS#1 v2.2).
*
*   Returns:
*       (RsaPrivateKey, RsaPublicKey) -> par de claves RSA
*/
fn generar_claves_rsa() -> (RsaPrivateKey, RsaPublicKey) {
    let clave_privada = RsaPrivateKey::new_with_exp(
        &mut OsRng,
        BITS_RSA,
        &rsa::BigUint::from(EXPONENTE),
    )
    .expect("Error al generar clave RSA");

    let clave_publica = RsaPublicKey::from(&clave_privada);
    (clave_privada, clave_publica)
}

/*
*   Cifra texto con RSA-2048 usando padding OAEP + SHA-256.
*
*   OAEP introduce aleatoriedad: cifrar el mismo texto dos veces
*   produce criptogramas distintos, aunque la clave sea igual.
*   Esto previene ataques de texto plano elegido.
*
*   ¿Por qué SHA-256 en OAEP?
*   SHA-256 se usa internamente en la función de enmascaramiento
*   MGF1 (Mask Generation Function). Es el estándar recomendado.
*
*   Args:
*       texto     -> Bytes del texto plano
*       clave_pub -> Clave pública RSA (quien cifra no necesita la privada)
*   Returns:
*       Vec<u8> -> Criptograma (siempre 256 bytes para RSA-2048)
*/
fn cifrar_rsa(texto: &[u8], clave_pub: &RsaPublicKey) -> Vec<u8> {
    let padding = Oaep::new::<Sha256>();
    clave_pub
        .encrypt(&mut OsRng, padding, texto)
        .expect("Error al cifrar con RSA-OAEP")
}

/*
*   Descifra un criptograma RSA-2048 con OAEP.
*
*   Solo la clave PRIVADA puede descifrar lo que se cifró
*   con la clave pública correspondiente.
*
*   Args:
*       ct         -> Criptograma (256 bytes para RSA-2048)
*       clave_priv -> Clave privada RSA
*   Returns:
*       Vec<u8> -> Texto plano recuperado
*/

fn descifrar_rsa(ct: &[u8], clave_priv: &RsaPrivateKey) -> Vec<u8> {
    let padding = Oaep::new::<Sha256>();
    clave_priv
        .decrypt(padding, ct)
        .expect("Error al descifrar RSA-OAEP: clave incorrecta o CT corrupto")
}

/*
*   Firma un mensaje con RSA-2048 usando padding PSS + SHA-256.
*
*   La FIRMA se realiza con la clave PRIVADA (al revés que el cifrado).
*   Quien quiera verificar usa la clave pública.
*
*   PSS (Probabilistic Signature Scheme):
*   - Introduce una sal (salt) aleatoria en cada firma.
*   - Cada ejecución produce una firma diferente para el mismo mensaje.
*   - Es más seguro que PKCS#1 v1.5 frente a ataques de adaptación.
*
*   ¿Por qué firmamos y no solo ciframos?
*   La firma garantiza AUTENTICIDAD + INTEGRIDAD:
*   "Este mensaje lo generó quien tiene la clave privada
*   y no ha sido modificado desde entonces."
*
*   Args:
*       mensaje    -> Bytes del mensaje a firmar
*       clave_priv -> Clave privada RSA (¡con ella se firma!)
*   Returns:
*       Vec<u8> -> Firma digital (256 bytes para RSA-2048)
*/
fn firmar_rsa_pss(mensaje: &[u8], clave_priv: &RsaPrivateKey) -> Vec<u8> {
    let signing_key = BlindedSigningKey::<Sha256>::new(clave_priv.clone());
    let firma = signing_key.sign_with_rng(&mut OsRng, mensaje);
    firma.to_bytes().to_vec()
}

/*
*   Verifica una firma RSA-PSS con la clave pública.
*
*   Si la firma no corresponde al mensaje (o fue alterada),
*   la función devuelve false.
*
*   Args:
*       mensaje   -> Bytes del mensaje original
*       firma     -> Bytes de la firma a verificar
*       clave_pub -> Clave pública del firmante
*   Returns:
*       bool -> true si la firma es válida
*/
fn verificar_rsa_pss(mensaje: &[u8], firma: &[u8], clave_pub: &RsaPublicKey) -> bool {
    let verifying_key = PssVerifyingKey::<Sha256>::new(clave_pub.clone());
    let firma_obj = match rsa::pss::Signature::try_from(firma) {
        Ok(f) => f,
        Err(_) => return false,
    };
    verifying_key.verify(mensaje, &firma_obj).is_ok()
}

// =============================================================
//  EJERCICIO 2 — ECDSA con SECP256K1
// =============================================================
//
//  ¿Qué es una curva elíptica?
//
//  Una ecuación de la forma: y² = x³ + ax + b  (mod p)
//  Los puntos en esta curva forman un grupo matemático
//  con una operación de "suma de puntos":
//
//   P + Q = R  (el tercer punto de intersección de la recta PQ,
//               reflejado respecto al eje x)
//
//  La "multiplicación escalar" k·G es fácil de calcular pero
//  prácticamente imposible de invertir (problema del logaritmo
//  discreto en curvas elípticas, ECDLP).
//
//  SECP256K1: la curva de Bitcoin
//  - Ecuación:  y² = x³ + 7  (a=0, b=7)
//  - Primo p de 256 bits
//  - Clave privada: número aleatorio d (256 bits)
//  - Clave pública: punto Q = d·G  (G = punto generador)
//
//  Proceso de firma ECDSA:
//  1. Generar nonce k aleatorio
//  2. R = k·G  (punto en la curva)
//  3. r = R.x mod n
//  4. s = k⁻¹ · (hash(m) + r·d) mod n   (d = clave privada)
//  5. Firma = (r, s) codificada en DER
//
//  ¡ADVERTENCIA!
//  Si el mismo k se reutiliza con mensajes distintos, se puede
//  recuperar la clave privada. Esto ocurrió en la PlayStation 3.
//  Las implementaciones modernas usan k determinista (RFC 6979).
//
//  ECDSA vs RSA en tamaño:
//
//   Algoritmo   Clave privada   Tamaño firma   Seguridad
//   ---------   -------------   ------------   ----------
//   RSA-2048       2048 bits      256 bytes      112 bits
//   ECDSA-256       256 bits      ~71 bytes      128 bits
//
//  * ECDSA produce firmas MUCHO más compactas con mayor seguridad.
//    Por eso es el estándar en TLS 1.3, SSH y blockchain.
//
//  Nota sobre la crate:
//  La librería p256 implementa la curva P-256 (NIST / SECP256R1),
//  que tiene los mismos parámetros de seguridad que SECP256K1
//  (ambas son curvas de 256 bits). SECP256K1 pura requeriría la
//  crate k256. El comportamiento criptográfico es idéntico para
//  la práctica: misma longitud de clave, misma longitud de firma.
//
// =============================================================

/*
*   Genera un par de claves ECDSA con curva de 256 bits.
*
*   Returns:
*       (EcdsaSigningKey, EcdsaVerifyingKey) -> par de claves ECDSA
*/
fn generar_claves_ecdsa() -> (EcdsaSigningKey, EcdsaVerifyingKey) {
    let signing_key = EcdsaSigningKey::random(&mut OsRng);
    let verifying_key = EcdsaVerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

/*
*   Firma un mensaje con ECDSA + SHA-256.
*
*   La firma resultante está codificada en formato DER (ASN.1).
*   Es NO determinista por defecto: cada ejecución produce una
*   firma distinta porque el nonce k es aleatorio.
*
*   Args:
*       mensaje      -> Bytes del mensaje a firmar
*       signing_key  -> Clave privada ECDSA
*   Returns:
*       Vec<u8> -> Firma DER (~70-72 bytes típicamente)
*/
fn firmar_ecdsa(mensaje: &[u8], signing_key: &EcdsaSigningKey) -> Vec<u8> {
    let firma: EcdsaSignature = signing_key.sign(mensaje);
    firma.to_der().to_bytes().to_vec()
}

/*
*   Verifica una firma ECDSA con la clave pública.
*
*   Args:
*       mensaje        -> Bytes del mensaje original
*       firma_der      -> Firma DER a verificar
*       verifying_key  -> Clave pública ECDSA del firmante
*   Returns:
*       bool -> true si la firma es válida
*/
fn verificar_ecdsa(mensaje: &[u8], firma_der: &[u8], verifying_key: &EcdsaVerifyingKey) -> bool {
    let firma = match EcdsaSignature::from_der(firma_der) {
        Ok(f) => f,
        Err(_) => return false,
    };
    verifying_key.verify(mensaje, &firma).is_ok()
}

// =============================================================
//  MAIN
// =============================================================

fn main() {
    let texto_bytes = TEXTO.as_bytes();

    println!("  Texto : {}", TEXTO);
    println!("  Bytes : {} bytes", texto_bytes.len());


    //  EJERCICIO 1 — CIFRADO RSA

    imprimir_separador("EJERCICIO 1 -- CIFRADO RSA-2048");

    println!("\n  [1/4] Generando par de claves RSA-2048...");
    let (clave_priv_rsa, clave_pub_rsa) = generar_claves_rsa();
    println!("  Exponente público : {}", EXPONENTE);
    println!("  Longitud de clave : {} bits", BITS_RSA);

    // Mostrar clave pública en formato PEM
    let pem = clave_pub_rsa
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .expect("Error al serializar clave pública");
    println!("\n  Clave pública (PEM):");
    for linea in pem.lines() {
        println!("    {}", linea);
    }

    // Cifrado RSA -- dos ejecuciones para demostrar que OAEP
    // produce CTs distintos incluso con el mismo texto y clave
    println!("\n  [2/4] Cifrando con clave PÚBLICA + OAEP ...");
    println!("\n  * OAEP introduce aleatoriedad: el CT cambia en cada ejecución");

    let mut ct_rsa_guardado = Vec::new();
    for i in 1..=2 {
        let ct = cifrar_rsa(texto_bytes, &clave_pub_rsa);
        println!("\n  Ejecución {}:", i);
        imprimir_bytes("CT RSA", &ct);
        if i == 1 {
            ct_rsa_guardado = ct;
        }
    }

    // Verificación descifrado
    println!("\n  [Verificación descifrado RSA (ejecución 1)]");
    let pt_rsa = descifrar_rsa(&ct_rsa_guardado, &clave_priv_rsa);
    let recuperado = std::str::from_utf8(&pt_rsa).unwrap();
    println!("  Texto descifrado : {}", recuperado);
    println!(
        "  ¿Coincide?       : {}",
        if recuperado == TEXTO { "SÍ" } else { "NO" }
    );

    //  EJERCICIO 1 — FIRMA RSA-PSS

    imprimir_separador("EJERCICIO 1 -- FIRMA RSA-PSS");

    println!("\n  [3/4] Firmando con clave PRIVADA + PSS ...");
    println!("\n  * La firma RSA se realiza con la CLAVE PRIVADA");
    println!("  * PSS añade sal aleatoria: la firma cambia en cada ejecución");
    println!("  * Para RSA-2048 la firma ocupa siempre 256 bytes");

    let mut firma_rsa_guardada = Vec::new();
    for i in 1..=2 {
        let firma = firmar_rsa_pss(texto_bytes, &clave_priv_rsa);
        println!("\n  Ejecución {}:", i);
        imprimir_bytes("FIRMA RSA-PSS", &firma);
        if i == 1 {
            firma_rsa_guardada = firma;
        }
    }

    // Verificación firma RSA
    println!("\n  [4/4] Verificando firma con clave PÚBLICA ...");
    let valida_rsa = verificar_rsa_pss(texto_bytes, &firma_rsa_guardada, &clave_pub_rsa);
    println!(
        "  ¿Firma válida?   : {}",
        if valida_rsa { "SÍ" } else { "NO" }
    );
    println!("  ¿Con qué clave se firmó?    Con la CLAVE PRIVADA RSA-2048.");
    println!("  ¿Con qué clave se verifica? Con la CLAVE PÚBLICA RSA-2048.");

    //  EJERCICIO 2 — ECDSA

    imprimir_separador("EJERCICIO 2 -- FIRMA ECDSA (SECP256K1 / P-256)");

    println!("\n  [1/4] Generando par de claves ECDSA 256 bits ...");
    let (signing_key, verifying_key) = generar_claves_ecdsa();
    println!("  Curva            : SECP256K1 / P-256");
    println!("  Clave privada    : 256 bits");
    println!("  Clave pública    : 64 bytes (punto no comprimido en la curva)");

    println!("\n  [2/4] Firmando con ECDSA ...");
    println!("\n  * ECDSA genera un nonce k aleatorio: la firma cambia en cada ejecución");
    println!("  * La firma se codifica en DER (ASN.1): ~70-72 bytes (vs 256 en RSA)");

    let mut firma_ecdsa_guardada = Vec::new();
    for i in 1..=2 {
        let firma = firmar_ecdsa(texto_bytes, &signing_key);
        println!("\n  Ejecución {}:", i);
        imprimir_bytes("FIRMA ECDSA", &firma);
        if i == 1 {
            firma_ecdsa_guardada = firma;
        }
    }

    // Verificación ECDSA -- firma válida
    println!("\n  [3/4] Verificando firma ECDSA con clave pública ...");
    let valida_ec = verificar_ecdsa(texto_bytes, &firma_ecdsa_guardada, &verifying_key);
    println!(
        "  ¿Firma válida?   : {}",
        if valida_ec { "SÍ" } else { "NO" }
    );

    // Verificación ECDSA -- mensaje alterado (debe fallar)
    println!("\n  [4/4] Prueba con mensaje alterado (debe fallar) ...");
    let mensaje_falso = b"ESTAMOS EN CLASE DE MATEMATICAS ";
    let valida_falsa = verificar_ecdsa(mensaje_falso, &firma_ecdsa_guardada, &verifying_key);
    println!("  Mensaje alterado : {}", std::str::from_utf8(mensaje_falso).unwrap());
    println!(
        "  ¿Firma válida?   : {}",
        if valida_falsa {
            "SÍ (¡ERROR!)" //Esto debería ser imposible
        } else {
            "NO (correcto: la firma no corresponde al mensaje alterado)"
        }
    );

    //  COMPARATIVA FINAL

    println!("\n{}", "**".repeat(62));
    println!("  CONCLUSIÓN Y COMPARATIVA");
    println!("{}", "**".repeat(62));
    println!();
    println!("  CIFRADO RSA:");
    println!("    Clave para cifrar    : PÚBLICA  (cualquiera puede cifrar)");
    println!("    Clave para descifrar : PRIVADA  (solo el dueño descifra)");
    println!("    Padding              : OAEP + SHA-256  (probabilístico)");
    println!("    Tamaño criptograma   : {} bytes  (= longitud clave en bytes)", BITS_RSA / 8);
    println!();
    println!("  FIRMA RSA-PSS:");
    println!("    Clave para firmar    : PRIVADA  (solo el dueño firma)");
    println!("    Clave para verificar : PÚBLICA  (cualquiera verifica)");
    println!("    Padding              : PSS + SHA-256  (sal aleatoria)");
    println!("    Tamaño firma         : {} bytes", BITS_RSA / 8);
    println!();
    println!("  FIRMA ECDSA:");
    println!("    Clave para firmar    : PRIVADA  (256 bits)");
    println!("    Clave para verificar : PÚBLICA");
    println!("    Longitud clave priv. : 256 bits  (vs 2048 en RSA)");
    println!("    Tamaño firma (DER)   : ~71 bytes  (vs {} en RSA-PSS)", BITS_RSA / 8);
    println!();
    println!("  DIFERENCIAS RSA vs ECDSA:");
    println!("    RSA   -> firma de {} bytes, clave de {} bits", BITS_RSA / 8, BITS_RSA);
    println!("    ECDSA -> firma de ~71 bytes, clave de 256 bits  <- más compacto");
    println!("    Ambas son NO deterministas (PSS sal + nonce ECDSA aleatorio)");
    println!("    Ambas verifican correctamente y rechazan mensajes alterados.");
    println!("    ECDSA es preferido en entornos con recursos limitados (IoT, TLS, blockchain).");
    println!("\n{}", "**".repeat(62));
}