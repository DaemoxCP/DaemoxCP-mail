package org.daemoxcp.mail.util;

/**
 * The mark of an error already translated for the page, which ErrorText lets through. Two types carry it, because
 * the caller tells them apart: ShownException (IllegalStateException) and ShownException.Argument
 * (IllegalArgumentException, for wrong arguments: SSLMailServer catches exactly that one around
 * AddressTransform.destinations).
 */
public interface TranslatedError {
}
