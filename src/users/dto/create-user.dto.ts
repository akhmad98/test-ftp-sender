export class CreateUserDto {
  id: number;
  email: string;
  hash: string;
  hashedRt: string | null;
}
