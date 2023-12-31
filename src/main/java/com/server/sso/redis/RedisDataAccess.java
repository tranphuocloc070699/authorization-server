package com.server.sso.redis;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import lombok.RequiredArgsConstructor;

@Repository
@RequiredArgsConstructor
public class RedisDataAccess {
  public static final String HASH_KEY = "User";

  private final RedisTemplate<Object,Object> template;


  /*
  * Type:CACHED
  * Uses: Find all cached user
  * */
  public List<RedisUser> findAll(){
    List<Object> redisUserObjects = template.opsForHash().values(HASH_KEY);
    // Convert List<Object> to List<RedisUser>
    return redisUserObjects.stream()
        .map(object -> (RedisUser) object)
        .collect(Collectors.toList());
  }

  /*
   * type: CACHED
   * Uses: Find cached user
   * */
  public RedisUser findRedisUserByEmail(String email){
    return (RedisUser) template.opsForHash().get(HASH_KEY,email);
  }

  /*
   * Type: TEMPORARY
   * Uses: Find temporary user
   * */
  public RedisUser findUserTemporaryByKey(String key){
    return (RedisUser) template.opsForValue().get(key);
  }

  /*
   * Type: CACHED
   * Uses: Save cached user
   * Notes: Signup or login success -> save user info in redis
   * */
  public RedisUser save(RedisUser user){
    template.opsForHash().put(HASH_KEY,user.getEmail(),user);
    return user;
  }

  /*
   * Type: TEMPORARY
   * Uses: Save temporary user
   * Notes: For signup verify, auto delete when user signup but not confirm mail
   * */
  public void saveTemporary(String key ,RedisUser user,Integer ttl){
        if(ttl==null) ttl = 60;
        template.opsForValue().set(key,user);
        template.expire(key,ttl, TimeUnit.SECONDS);
  }

  /*
   * Type: TEMPORARY
   * Uses: Delete temporary user
   * Notes: When signup successfully
   * */
  public void deleteUserTemporary(String key){
     template.delete(key);
  }

  /*
   * Type: CACHED
   * Uses: Delete cached user
   * */
  public String deleteRedisUserByEmail(String email){
    template.opsForHash().delete(HASH_KEY,email);
    return "user removed !!";
  }
}
