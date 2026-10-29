import { Type } from 'class-transformer';
import {
  IsInt,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from 'class-validator';

export const DEFAULT_PAGE_SIZE = 20;
export const MAX_PAGE_SIZE = 100;
const MAX_SEARCH_LENGTH = 200;

export class PageQueryDto {
  /** Case-insensitive substring over names, e-mails and did:keys. */
  @IsOptional()
  @IsString()
  @MaxLength(MAX_SEARCH_LENGTH)
  q?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(MAX_PAGE_SIZE)
  pageSize: number = DEFAULT_PAGE_SIZE;
}

export type Page<T> = {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
};
