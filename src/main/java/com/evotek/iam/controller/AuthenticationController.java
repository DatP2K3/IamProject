package com.evotek.iam.controller;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.response.AuthenticationResponseDTO;
import com.evotek.iam.dto.response.IntrospectResponseDTO;
import com.evotek.iam.service.AuthService;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthService authService;

    @PostMapping("/token")
    public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequestDTO request) {
        authService.authenticate(request);
        return ResponseEntity.ok("Otp sent to email");
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<AuthenticationResponseDTO> verifyOtp(@RequestBody VerifyOtpRequestDTO verifyOtpRequestDTO){
        AuthenticationResponseDTO result = authService.verifyOtp(verifyOtpRequestDTO);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/introspect")
    public ResponseEntity<IntrospectResponseDTO> authenticate(@RequestBody IntrospectRequestDTO request)
            throws ParseException, JOSEException {
        IntrospectResponseDTO result = authService.introspect(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(HttpServletRequest request)
            throws ParseException, JOSEException {
        AuthenticationResponseDTO result = authService.refreshToken(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, @RequestBody IntrospectRequestDTO refreshToken)
            throws ParseException, JOSEException {
        authService.logout(request, refreshToken);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> requestPasswordReset(@RequestParam String email) {
        authService.requestPasswordReset(email);
        return ResponseEntity.ok("Reset password link sent to email");
    }

    @PatchMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam String token, @RequestBody PasswordRequestDTO passwordRequestDTO) {
        authService.resetPassword(token, passwordRequestDTO.getNewPassword());
        return ResponseEntity.ok("Password successfully reset");
    }
}