import { IsString, MinLength } from 'class-validator';


export class RegisterUserDto {
    @IsString()
    name: string;

    @IsString()
    @MinLength(3)
    email: string;

    @MinLength(6)
    password: string;
}