package com.server.sso.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class RedisDataAccess {
    public static final String HASH_KEY = "User";

  private final RedisTemplate template;

  public RedisUser save(RedisUser user){
    template.opsForHash().put(HASH_KEY,user.getEmail(),user);
    return user;
  }

  public List<RedisUser> findAll(){
    return template.opsForHash().values(HASH_KEY);
  }

  public RedisUser findRedisUserByEmail(String email){
    return (RedisUser) template.opsForHash().get(HASH_KEY,email);
  }


  public String deleteRedisUserByEmail(String email){
    template.opsForHash().delete(HASH_KEY,email);
    return "user removed !!";
  }
}
