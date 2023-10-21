package com.teqmonic.springsecurityjwt.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.teqmonic.springsecurityjwt.entity.RoleEntity;

public interface RoleRepository extends CrudRepository<RoleEntity, Long> {

	Optional<RoleEntity> findByAuthority(String authority);
}
