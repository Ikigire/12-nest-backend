import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcryptjs from "bcryptjs";

import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt.payload';
import { LoginResponse } from './interfaces/login-response';

import { CreateUserDto, UpdateUserDto, LoginDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,

    private jwtService: JwtService
  ) { }

  /**
   * Método para la creación de usuarios dentro de la base de datos
   * @param createUserDto Objeto que contiene los datos requeridos para la generación de nuevos usuarios
   * @returns una Promesa con los datos del usuario
   */
  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      // 1. Encriptar la contraseña
      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

      // 2. Guardar el usuario
      await newUser.save();
      const { password:_, ...user} = newUser.toJSON();

      return user;

    } catch ( error ) {
      if ( error.code === 11000 ){
        throw new BadRequestException(`${ createUserDto.email } already exist!`);
      }

      throw new InternalServerErrorException('Something went wrong with the server!')
    }
  }

  /**
   * Método que permite a usuario loggeados registrar nuevos usuarios
   * @param registerUserDto Datos requeridoa para realizar el registro
   * @returns Una promesa con los datos del usuario registrado + el token de acceso para el usuario
   */
  async register( registerUserDto: RegisterUserDto ): Promise<LoginResponse> {
    try {
      const password = this.createRandomPassword( 8 );

      console.log(password);
      const user = await this.create({
        password,
        ...registerUserDto
      });
      
      return {
        user: user,
        token: this.getJwtToken( {id: user._id} )
      }
      
    } catch (error) {
      if ( error.response.statusCode == 400 )
        throw new BadRequestException(error.response.message)

      throw new InternalServerErrorException('Internal server error')
    }
  }

  /**
   * Permite realizar el login de un usuario revisando la exitencia del 'email' y el 'password'
   * @param loginDto Datos para la realización del Login de usuarios
   * @returns Una promesa con los datos del usuario y el token de acceso | error en cado de no econtrar el usuario
   */
  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const {email, password} = loginDto;

    const user = await this.userModel.findOne( {email} );

    if ( !user ) {
      throw new UnauthorizedException('Not valid credentials');
    }
    
    if ( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException('Not valid credentials')
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken( { id: user.id } )
    };
  }

  /**
   * Método que devuelve todos los usuarios registrados en la BD
   * @returns Todos los usuarios registrados enla base de datos
   */
  async findAll() {
    const results = await this.userModel.find();
    return results.map( res => {
      const { password, ...rest } = res.toJSON()
      return rest
    }  )
  }
  
  /**
   * Método que devuelve todos los usuarios registrados en la BD
   * @returns Todos los usuarios registrados enla base de datos
   */
  async searchEmail( email: string) {
    if ( !email ) 
      return [];

    const results = await this.userModel.find( {email} );

    return results.map( element => {
      const { email, ...rest } = element.toJSON()
      return { email }
    }  );
  }

  /**
   * Permite realizar la búsqueda de un usuario por su ID
   * @param id Id del usuario a buscar
   * @returns Objeto con los datos del usuario
   */
  async findUserById( id: string ) {
    const user = await this.userModel.findById( id );

    const {password, ...rest} = user.toJSON();
    return rest;
  }


  // async findOne(id: string) {

  //   const user = await this.userModel.findById( id );

  //   if ( !user ) {
  //     throw new NotFoundException();
  //   }

  //   // console.log(user.toJSON());
    
  //   // return user;
  //   const { password, ...resp } = user.toJSON();
  //   return resp;
  // }

  // update(id: number, updateUserDto: UpdateUserDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }

  getJwtToken( payload: JwtPayload) {
    const token = this.jwtService.sign(payload);

    return token;
  }

  createRandomPassword( longitud: number ): string {
    const banco = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let pass = '';

    for (let x = 0; x < longitud; x++) {
      pass += banco.charAt( Math.floor( Math.random() * banco.length ) );
    }

    return pass;
  }
}
