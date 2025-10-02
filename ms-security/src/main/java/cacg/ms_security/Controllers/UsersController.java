package cacg.ms_security.Controllers;

import cacg.ms_security.Models.Session;
import cacg.ms_security.Models.User;
import cacg.ms_security.Repositories.SessionRepository;
import cacg.ms_security.Repositories.UserRepository;
import cacg.ms_security.Services.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/users")
public class UsersController {
    @Autowired
    private UserRepository theUserRepository;

    @Autowired
    private SessionRepository theSessionRepository;

    @Autowired
    private EncryptionService theEncryptionService;

    @GetMapping("")
    public List<User> find() {
        return this.theUserRepository.findAll();
    }



    @GetMapping("{id}")
    public User findById(@PathVariable String id) {
        User theUser = this.theUserRepository.findById(id).orElse(null);
        return theUser;
    }

    @PostMapping
    public User create(@RequestBody User newUser) {
        boolean emailExists = theUserRepository.findAll()
                .stream()
                .anyMatch(user -> user.getEmail().equals(newUser.getEmail()));

        if (emailExists) {
            throw new RuntimeException("Ya existe un usuario con este correo electrónico");
        }

        newUser.setPassword(theEncryptionService.convertSHA256(newUser.getPassword()));
        return this.theUserRepository.save(newUser);
    }

    @PutMapping("{id}")
    public User update(@PathVariable String id, @RequestBody User newUser) {
        User actualUser = this.theUserRepository.findById(id).orElse(null);
        if (actualUser != null) {
            actualUser.setName(newUser.getName());
            actualUser.setEmail(newUser.getEmail());
            actualUser.setPassword(this.theEncryptionService.convertSHA256(newUser.getPassword()));
            this.theUserRepository.save(actualUser);
            return actualUser;
        } else {
            return null;
        }
    }

    @DeleteMapping("{id}")
    public void delete(@PathVariable String id) {
        User theUser = this.theUserRepository.findById(id).orElse(null);
        if (theUser != null) {
            this.theUserRepository.delete(theUser);
        }
    }

    @PutMapping("{userId}/session/{idSession}")
    public void matchSession(@PathVariable String userId, @PathVariable String idSession) {
        Session theSession=this.theSessionRepository.findById(idSession).orElse(null);
        User theUser=this.theUserRepository.findById(userId).orElse(null);
        if(theUser!=null && theSession!=null){
            theSession.setUser(theUser);
            this.theSessionRepository.save(theSession);
        }
    }
}