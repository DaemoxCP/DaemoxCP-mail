package org.daemoxcp.mail.util;

/**
 * Il segno di un errore gia' tradotto per la pagina, che ErrorText lascia passare. Due tipi lo portano, perche' chi
 * chiama distingue: ShownException (IllegalStateException) e ShownException.Argument (IllegalArgumentException, per gli
 * argomenti sbagliati: SSLMailServer cattura proprio quella attorno ad AddressTransform.destinations).
 */
public interface TranslatedError {
}
