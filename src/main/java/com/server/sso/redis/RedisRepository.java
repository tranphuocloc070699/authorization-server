package com.server.sso.redis;

import com.server.sso.auth.RedisUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

//@Repository
public interface RedisRepository extends CrudRepository<RedisUser,String> {

//  public static final String HASH_KEY = "User";
//  @Autowired
//  private RedisTemplate template;
//
//  public RedisUser save(RedisUser user){
//    template.opsForHash().put(HASH_KEY,user.getId(),user);
//    return user;
//  }
//
//  public List<RedisUser> findAll(){
//    return template.opsForHash().values(HASH_KEY);
//  }
//
//  public RedisUser findRedisUserById(int id){
//    return (RedisUser) template.opsForHash().get(HASH_KEY,id);
//  }
//
//
//  public String deleteRedisUser(int id){
//    template.opsForHash().delete(HASH_KEY,id);
//    return "user removed !!";
//  }
}
