package com.server.sso.redis;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class RedisDataAccess {
    public static final String HASH_KEY = "User";

  private final RedisTemplate template;

  public RedisUser save(RedisUser user){
    template.opsForHash().put(HASH_KEY,user.getEmail(),user);
    return user;
  }
  public RedisUser saveTemporary(String key ,RedisUser user,Integer ttl){
        if(ttl==null) ttl = 60;
        template.opsForValue().set(key,user);
        template.expire(key,ttl, TimeUnit.SECONDS);
    return user;
  }
  public RedisUser findUserTemporaryByKey(String key){
    return (RedisUser) template.opsForValue().get(key);
  }
  public Boolean deleteUserTemporary(String key){
   return  template.delete(key);
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
