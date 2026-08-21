import 'dart:io';

import 'package:flutter/services.dart';

import '../../msal_auth.dart';
import '../utils/extensions.dart';
import '../utils/utils.dart';

part 'multiple_account_pca.dart';
part 'single_account_pca.dart';

/// This is the super class for MSAL public client application. developer
/// should use the child classes to create the app based on the need.
class PublicClientApplication {
  PublicClientApplication();

  /// Acquire token interactively, will pop-up webUI. this flow is called as
  /// Interactive flow and so it skips the cache lookup.
  Future<AuthenticationResult> acquireToken({
    /// Access levels your application is requesting from the
    /// Microsoft identity platform on behalf of a user.
    required List<String> scopes,

    /// Initial UI option.
    Prompt prompt = Prompt.whenRequired,

    /// It should be valid "email id" or "username" or "unique identifier".
    /// Value is used as an identity provider to pre-fill a user's
    /// email address or username in the login form.
    String? loginHint,

    /// Authority URL to override the default authority.
    /// Required for "B2C" scenarios where different policies require
    /// different authorities.
    String? authority,

    /// Claims request from a Conditional Access challenge, as a JSON string.
    ///
    /// When a resource server answers 401 with
    /// `WWW-Authenticate: Bearer error="insufficient_claims", claims="<base64>"`,
    /// decode that value and pass it here. Without it the authorization
    /// request omits the requirement and returns the same insufficient token,
    /// so the caller ends up in a sign-in loop that can never succeed.
    ///
    /// See https://learn.microsoft.com/entra/identity-platform/claims-challenge
    String? claims,

    /// Custom WebView configuration for iOS/MacOS platforms.
    /// For iOS, it is only used when broker is webView.
    CustomWebViewConfig? customWebViewConfig,
  }) async {
    assert(scopes.isNotEmpty, 'Scopes can not be empty');
    final arguments = <String, dynamic>{
      'scopes': scopes,
      'prompt': prompt.name,
      'loginHint': loginHint,
      'authority': authority,
      'claims': claims,
      'broker': Broker.msAuthenticator.name,
      if (Platform.isIOS || Platform.isMacOS)
        'customWebViewConfig': customWebViewConfig?.toJson(),
    };
    try {
      final result =
          await kMethodChannel.invokeMethod('acquireToken', arguments);
      return AuthenticationResult.fromJson(
        (result as Map).cast<String, dynamic>(),
      );
    } on PlatformException catch (e) {
      throw e.convertToMsalException();
    }
  }

  /// Perform acquire token silent call. If there is a valid access token in
  /// the cache, the sdk will return the access token; If no valid access token
  /// exists, the sdk will try to find a refresh token and use the refresh token
  /// to get a new access token. If refresh token does not exist or it fails
  /// the refresh, exception will be sent.
  Future<AuthenticationResult> acquireTokenSilent({
    /// Access levels your application is requesting from the
    /// Microsoft identity platform on behalf of a user.
    required List<String> scopes,

    /// Account identifier, basically id from account object.
    /// Required for multiple account mode.
    String? identifier,

    /// Optional authority URL to override the cached account's authority.
    /// Required for B2C scenarios where you want to refresh tokens using
    /// a different policy than the one used for initial authentication.
    String? authority,

    /// Claims request from a Conditional Access challenge, as a JSON string.
    ///
    /// A silent call carrying claims will usually fail with
    /// [MsalUiRequiredException]; that is expected. The caller should then fall
    /// back to [acquireToken] with the same claims, because only an interactive
    /// request can satisfy a fresh-MFA requirement.
    String? claims,
  }) async {
    assert(scopes.isNotEmpty, 'Scopes can not be empty');
    if (this is MultipleAccountPca) {
      assert(
        identifier != null,
        'Identifier can not be null for multiple account mode',
      );
    }
    final arguments = <String, dynamic>{
      'scopes': scopes,
      'identifier': identifier,
      'authority': authority,
      'claims': claims,
    };
    try {
      final result =
          await kMethodChannel.invokeMethod('acquireTokenSilent', arguments);
      return AuthenticationResult.fromJson(
        (result as Map).cast<String, dynamic>(),
      );
    } on PlatformException catch (e) {
      throw e.convertToMsalException();
    }
  }

  /// Returns whether the application is being run on a device that is marked as
  /// a shared by administrator.
  /// Only `SingleAccountPublicClientApplications` may be used on shared devices.
  Future<bool> isSharedDevice() async {
    try {
      final result = await kMethodChannel.invokeMethod<bool>('isSharedDevice');
      return result ?? false;
    } on PlatformException catch (e) {
      throw e.convertToMsalException();
    }
  }
}
