package rs.urosvesic.authservice.exception;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ExceptionResponse
{
	private String message;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
	private LocalDateTime timestamp;

	public ExceptionResponse(final String message)
	{
		this.message = message;
		this.timestamp = LocalDateTime.now();
	}
}
