package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponse;
import com.evotek.iam.dto.request.PasswordRequestDTO;
import com.evotek.iam.dto.request.UserInforRequestDTO;
import com.evotek.iam.dto.request.UserRequestDTO;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.service.UserService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PUBLIC)
public class UserController {
    private final UserService userService;

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/users")
    ResponseEntity<ApiResponse<UserResponseDTO>> createUser(@RequestBody UserRequestDTO userRequestDTO) {
        UserResponseDTO userResponseDTO = userService.createUser(userRequestDTO);
        ApiResponse<UserResponseDTO> apiResponse = ApiResponse.<UserResponseDTO>builder()
                .data(userResponseDTO)
                .success(true)
                .code(201)
                .message("User created successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/users/{id}")
    ResponseEntity<ApiResponse<UserResponseDTO>> getUserById(@PathVariable int id) {
        UserResponseDTO userResponseDTO = userService.getUserById(id);
        ApiResponse<UserResponseDTO> apiResponse = ApiResponse.<UserResponseDTO>builder()
                .data(userResponseDTO)
                .success(true)
                .code(200)
                .message("User retrieved successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/users")
    ResponseEntity<ApiResponse<List<UserResponseDTO>>> getAllUsers() {
        List<UserResponseDTO> userResponseDTOs = userService.getAllUsers();
        ApiResponse<List<UserResponseDTO>> apiResponse = ApiResponse.<List<UserResponseDTO>>builder()
                .data(userResponseDTOs)
                .success(true)
                .code(200)
                .message("Users list retrieved successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @PatchMapping("/users/{id}/info")
    ResponseEntity<ApiResponse<UserResponseDTO>> updateInfoUser(@PathVariable int id, @RequestBody UserInforRequestDTO userInforRequestDTO) {
        UserResponseDTO userResponseDTO = userService.updateInfoUser(id, userInforRequestDTO);
        ApiResponse<UserResponseDTO> apiResponse = ApiResponse.<UserResponseDTO>builder()
                .data(userResponseDTO)
                .success(true)
                .code(200)
                .message("User info updated successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }

    @PreAuthorize("hasRole('ROLE_USER')")
    @PatchMapping("/users/{id}/password")
    ResponseEntity<ApiResponse<Void>> updatePassword(@PathVariable int id, @RequestBody PasswordRequestDTO passwordRequestDTO) {
        userService.updatePassword(id, passwordRequestDTO);
        ApiResponse<Void> apiResponse = ApiResponse.<Void>builder()
                .success(true)
                .code(200)
                .message("Password updated successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/users/avatar")
    public ResponseEntity<ApiResponse<String>> uploadAvatar(@RequestParam int id, @RequestParam("avatar") MultipartFile file) {
        String avatar = userService.updateAvatar(id, file);
        ApiResponse<String> apiResponse = ApiResponse.<String>builder()
                .data(avatar)
                .success(true)
                .code(200)
                .message("Avatar uploaded successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }


    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable int id) {
        userService.deleteUser(id);
        ApiResponse<Void> apiResponse = ApiResponse.<Void>builder()
                .success(true)
                .code(200)
                .message("User deleted successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
        return ResponseEntity.ok(apiResponse);
    }
}