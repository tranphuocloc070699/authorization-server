package com.server.sso.redis;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;


public interface RedisRepository extends CrudRepository<RedisUser,String> {
}
