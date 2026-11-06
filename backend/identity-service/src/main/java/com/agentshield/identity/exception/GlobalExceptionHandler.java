package com.agentshield.identity.exception;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.agentshield.identity.user.service.DuplicateUserEmailException;
import com.agentshield.identity.user.service.UserNotFoundException;
import com.agentshield.identity.membership.service.DuplicateOrganizationMembershipException;
import com.agentshield.identity.membership.service.OrganizationNotFoundException;
import com.agentshield.identity.onboarding.service.OrganizationOnboardingConflictException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidationFailure(MethodArgumentNotValidException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Request validation failed");
        problem.setTitle("Validation failed");
        List<Map<String, String>> fieldErrors = exception.getBindingResult().getFieldErrors().stream()
                .map(error -> Map.of(
                        "field", error.getField(),
                        "message", error.getDefaultMessage() == null ? "Invalid value" : error.getDefaultMessage()))
                .toList();
        problem.setProperty("errors", fieldErrors);
        return problem;
    }

    @ExceptionHandler(DuplicateOrganizationCodeException.class)
    public ProblemDetail handleDuplicateOrganizationCode(DuplicateOrganizationCodeException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, exception.getMessage());
        problem.setTitle("Duplicate organization code");
        return problem;
    }

    @ExceptionHandler(DuplicateUserEmailException.class)
    public ProblemDetail handleDuplicateUserEmail(DuplicateUserEmailException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, exception.getMessage());
        problem.setTitle("Duplicate user email");
        return problem;
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ProblemDetail handleUserNotFound(UserNotFoundException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, exception.getMessage());
        problem.setTitle("User not found");
        return problem;
    }

    @ExceptionHandler(OrganizationNotFoundException.class)
    public ProblemDetail handleOrganizationNotFound(OrganizationNotFoundException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, exception.getMessage());
        problem.setTitle("Organization not found");
        return problem;
    }

    @ExceptionHandler(DuplicateOrganizationMembershipException.class)
    public ProblemDetail handleDuplicateOrganizationMembership(
            DuplicateOrganizationMembershipException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, exception.getMessage());
        problem.setTitle("Duplicate organization membership");
        return problem;
    }

    @ExceptionHandler(OrganizationOnboardingConflictException.class)
    public ProblemDetail handleOnboardingConflict(OrganizationOnboardingConflictException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, exception.getMessage());
        problem.setTitle("Organization onboarding could not be completed");
        return problem;
    }
}
