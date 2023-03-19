package rs.urosvesic.authservice.exception;

import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.List;


@Log4j2
@ControllerAdvice
public class GlobalExceptionHandler
{

	@ExceptionHandler(RuntimeException.class)
	public ResponseEntity<String> handleRuntimeException(final RuntimeException ex)
	{
		log.error("Runtime exception: {}", ex.getMessage());
		return new ResponseEntity<>(ex.getMessage(), HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<List<String>> handleMethodArgumentNotValidException(final MethodArgumentNotValidException ex)
	{
		log.error("MethodArgumentNotValidException exception: {}", ex.getMessage());
		List<ObjectError> allErrors = ex.getAllErrors();
		List<String> collect = allErrors.stream().map(err -> err.getDefaultMessage()).toList();
		return new ResponseEntity<>(collect,HttpStatus.BAD_REQUEST);
	}

}
