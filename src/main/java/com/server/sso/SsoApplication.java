package com.server.sso;

import com.server.sso.redis.RedisDataAccess;
import com.server.sso.redis.RedisUser;
import com.server.sso.user.Provider;
import com.server.sso.user.Role;
import com.server.sso.user.User;
import com.server.sso.user.UserDataAccess;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Date;
import java.util.Optional;

@SpringBootApplication
@RequiredArgsConstructor
public class SsoApplication implements CommandLineRunner {
	private final PasswordEncoder passwordEncoder;
	private final UserDataAccess userDataAccess;
	private final RedisDataAccess redisDataAccess;
	public static void main(String[] args) {
		SpringApplication.run(SsoApplication.class, args);
	}
	
	@Override
	public void run(String... args) throws Exception {
		String email = "admin@admin.com";
		String adminName= "Administrator";
		String rawPassword = "Loc123456";
		String passwordEncoded = passwordEncoder.encode(rawPassword);
		Optional<User> userExisting = userDataAccess.findByEmail(email);
		
		if (userExisting.isPresent()) {
			RedisUser redisUser = redisDataAccess.findRedisUserByEmail(email);
			if (redisUser == null) {
				RedisUser redisAdmin = RedisUser.builder()
								.id(userExisting.get().getId().toString())
								.name(userExisting.get().getName())
								.email(userExisting.get().getEmail())
								.password(passwordEncoded)
								.provider(Provider.LOCAL)
								.role(Role.ADMIN)
								.refreshTokenVersion(0)
								.isUsing2FA(false)
								.secret(null)
								.createdAt(new Date())
								.updatedAt(new Date())
								.build();
				
				redisDataAccess.save(redisAdmin);
			}
			
			return;
		}
		
		
	
		User admin = userDataAccess.save(User.builder()
						.email(email)
						.role(Role.ADMIN)
						.provider(Provider.LOCAL)
						.name(adminName)
						.password(passwordEncoded)
						.isUsing2FA(false)
						.secret(null)
						.build());
		
		RedisUser redisAdmin = RedisUser.builder()
						.id(admin.getId().toString())
						.name(admin.getName())
						.email(admin.getEmail())
						.password(passwordEncoded)
						.provider(Provider.LOCAL)
						.role(Role.ADMIN)
						.refreshTokenVersion(0)
						.isUsing2FA(false)
						.secret(null)
						.createdAt(new Date())
						.updatedAt(new Date())
						.build();
		
		redisDataAccess.save(redisAdmin);
		
	}
}
