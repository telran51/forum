package telran.java51.post.dao;

import org.springframework.data.repository.CrudRepository;

import telran.java51.post.model.Post;

public interface PostRepository extends CrudRepository<Post, String> {

}
