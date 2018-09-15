const express = require(`express`);
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const hbs = require('hbs');
const moment = require('moment');
const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
const passport = require("passport");
const passportJWT = require("passport-jwt");

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt');
jwtOptions.secretOrKey = 'mySecret';

mongoose.connect(process.env.MONGODB_URI||'mongodb://localhost/test-jwt-2');
const Schema = mongoose.Schema;
const userSchema = new Schema({
    username: {type: String, required: true},
    password: {type: String, required: true}
});
const User = mongoose.model('user',userSchema);

const app = express();
const port = process.env.PORT || 3000;
app.listen(port,()=>{
    console.log(`Listening port ${port}`);
});

app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(bodyParser.json());

hbs.registerHelper('getCurrentYear', ()=>{
    return moment().format('MMM Do YY, h:mm:ss a');
});

hbs.registerPartials(__dirname+'/views/partials');
// app.set('views', path.join(__dirname,'/secs'));
app.set('view engine', 'hbs');

app.use(express.static(__dirname+'/styles'));

app.get('/', function(req, res){
    res.render('index.hbs');
});

app.post('/login', (req, res) => {
    let name = req.body.name;
    let pass = req.body.pass;
    console.log(req.body);
    User.find({username: name})
            .then((users)=>{
                console.log(users);
                if(users.length>0){
                    bcrypt.compare(pass, users[0].password, function(err, result) {
                        if(err){
                            res.render('index.hbs',{msg:'Error Try Again'});
                        }else{
                            if(result){
                                let payload = {_id: users[0]._id};
                                let token = jwt.sign(payload, jwtOptions.secretOrKey,  {expiresIn: '10s'});
                                res.render('main.hbs',{
                                    name: users[0].username,
                                    pass: users[0].password,
                                    token: token
                                });
                            }else{
                                res.render('index.hbs',{msg:'Wrong password'});
                            }
                        }
                    });
                }
                else{
                    res.render('index.hbs',{msg:'Access Denied'});
                }
        }).catch((e)=>{
            console.log(e);
        });


});

app.post('/signin', (req, res) => {
    res.render('signin.hbs',{
        name: req.body.name,
        pass: req.body.pass,
    });
});


app.post('/register', (req, res) => {
    let name = req.body.name;
    let pass = req.body.pass1;

    User.find({username: name, password:pass})
    .then((users)=>{
        console.log(users);
        if(users.length>0){
            res.render('signin.hbs',{msg:'Invalid User'});
        }
        else{
            bcrypt.genSalt(10,(err,salt)=>{
                bcrypt.hash(pass, salt, (err, hashedPass)=>{
                    const user1 = new User({username: name, password: pass});
                    user1.save().then(()=>{
                        res.render('index.hbs');
                    }).catch((e)=>{
                        console.log(e);
                    });
                });
            });
        }
}).catch((e)=>{
    console.log(e);
});

});

//----------------------------------------------------------------
const strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next) {
    console.log('payload received', jwt_payload);
    // usually this would be a database call:
    User.find({_id: jwt_payload._id}).then((user)=>{
        if (user[0]) {
            next(null, user[0]);
          } else {
            next(null, false);
          }
    })
  });
//----------------------------------------------------------------

  passport.use(strategy);
  app.use(passport.initialize());


  app.get("/secret", passport.authenticate('jwt', { session: false }), function(req, res){
      console.log('Great');
    res.json({message: `Success! You can not see this without a token`});
  });